// Copyright 2025 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use super::default_registries::get_default_registries;
use super::search::TappletManifest;
use crate::wallet::Wallet;
use anyhow::{Context, anyhow};
use blake2::Blake2b512;
use blake2::Digest;
use blake2::digest::Update;
use log::debug;
use std::path::Path;
use tari_crypto::keys::PublicKey;
use tari_crypto::keys::SecretKey;
use tari_crypto::ristretto::RistrettoPublicKey;
use tari_crypto::ristretto::RistrettoSecretKey;
use tari_crypto::tari_utilities::ByteArray;
use tari_ootle_common_types::Epoch;
use tari_ootle_wallet_sdk::models::KeyIdOrPublicKey;
use tari_ootle_wallet_sdk::models::KeyType;
use tari_tapplet_lib::TappletRegistry;
use tari_template_lib_types::crypto::RistrettoPublicKeyBytes;

/// Install a tapplet from a registry
pub async fn install_from_registry(
    registry: Option<String>,
    name: &str,
    cache_directory: &Path,
) -> anyhow::Result<()> {
    let default_registries = get_default_registries();

    // Find the tapplet in registries
    let mut found_manifest: Option<(String, TappletManifest, std::path::PathBuf)> = None;

    dbg!("here");
    for (reg_name, _url) in default_registries {
        dbg!("checking registry:", &reg_name);
        // Skip if specific registry requested and this isn't it
        if let Some(ref requested_registry) = registry
            && reg_name != requested_registry
        {
            debug!("skipping registry: {}", &reg_name);
            continue;
        }

        dbg!("looking in registry:", &reg_name);

        let registry_dir = cache_directory.join("registries");
        let mut registry = TappletRegistry::new(name, url, registry_dir);

        registry.load().await?;

        // Look for the tapplet
        for (tapp_config, path) in registry.tapplets_and_dirs() {
            if tapp_config.name_matches(name) {
                found_manifest = Some((reg_name.to_string(), tapp_config, path));
                break;
            }
        }

        if found_manifest.is_some() {
            break;
        }
    }

    let (reg_name, tapp_config, tapplet_source_dir) =
        found_manifest.ok_or_else(|| anyhow!("Tapplet '{}' not found in registries", name))?;

    println!(
        "Found tapplet '{}' v{} in registry '{}'",
        tapp_config.name, tapp_config.version, reg_name
    );

    todo!();
    // Prompt for confirmation
    print!("\nInstall this tapplet? [y/N]: ");
    use std::io::{self, Write};
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if !input.trim().eq_ignore_ascii_case("y") {
        println!("Installation cancelled");
        return Ok(());
    }

    // Get accounts to install for
    // let accounts = if let Some(name) = account_name {
    //     vec![wallet.sdk().accounts_api().get_account_by_name(name)?]
    // } else {
    //     // Get all accounts
    //     wallet.sdk().accounts_api().get_many(0, 100)?
    // };

    // if accounts.is_empty() {
    //     anyhow::bail!("No accounts found. Create an account first.");
    // }

    // println!("\nInstalling tapplet for {} account(s)...", accounts.len());

    // Install the tapplet files
    let installed_dir = cache_directory.join("installed").join(&manifest.name);
    std::fs::create_dir_all(&installed_dir)?;

    // Copy tapplet files
    copy_dir_recursive(&tapplet_source_dir, &installed_dir)?;

    // Create child accounts for each parent account
    // Note: This requires database support for child accounts which may need to be implemented
    // for account in &accounts {
    //     println!(
    //         "  ✓ Installed for account '{}'",
    //         account.account().name.as_deref().unwrap_or("<unnamed>")
    //     );
    // }

    println!(
        "\n✓ Tapplet '{}' v{} installed successfully",
        manifest.name, manifest.version
    );

    Ok(())
}

/// Install a tapplet from a local path
pub async fn install_from_local(
    wallet: &mut Wallet,
    path: &Path,
    cache_directory: &Path,
    account_name: Option<&str>,
) -> anyhow::Result<()> {
    if !path.exists() {
        anyhow::bail!("Path does not exist: {:?}", path);
    }

    if !path.is_dir() {
        anyhow::bail!("Path must be a directory: {:?}", path);
    }

    // Read the manifest
    let manifest_path = path.join("manifest.toml");
    if !manifest_path.exists() {
        anyhow::bail!("No manifest.toml found in directory: {:?}", path);
    }

    let manifest_content =
        std::fs::read_to_string(&manifest_path).context("Failed to read manifest.toml")?;
    let manifest: TappletManifest =
        toml::from_str(&manifest_content).context("Failed to parse manifest.toml")?;

    println!(
        "Installing tapplet '{}' v{} from local path",
        manifest.name, manifest.version
    );
    if let Some(desc) = &manifest.description {
        println!("Description: {}", desc);
    }

    // Get accounts to install for
    let account = if let Some(name) = account_name {
        wallet.sdk().accounts_api().get_account_by_name(name)?
    } else {
        // Get all accounts
        wallet.sdk().accounts_api().get_default()?
    };

    println!(
        "\nInstalling tapplet for account '{}'",
        account.account().name.as_deref().unwrap_or("<unnamed>")
    );

    // Install the tapplet files
    let installed_dir = cache_directory.join("installed").join(&manifest.name);
    std::fs::create_dir_all(&installed_dir)?;

    // Copy tapplet files
    copy_dir_recursive(path, &installed_dir)?;

    // Create the new child account
    let key_id = account.view_only_key_id();
    let parent_view_key = wallet.sdk().key_manager_api().get_view_only_key(key_id)?;

    let tapplet_private_view_key_bytes = Blake2b512::new()
        .chain(b"tapplet_ootle_storage_address")
        .chain(parent_view_key.secret.as_bytes())
        .chain(hex::decode(&manifest.public_key)?)
        .finalize();
    let view_key = RistrettoSecretKey::from_uniform_bytes(&tapplet_private_view_key_bytes)
        .map_err(|e| anyhow::anyhow!(e))?;

    let label = format!("tapplet_view_key_{}", manifest.name);
    let new_account_name = format!("tapplet_{}", manifest.public_key);
    let new_key_id =
        wallet
            .sdk()
            .key_manager_api()
            .import_key(&label, &view_key, KeyType::ViewOnly)?;

    // let account_address = sdk
    //     .accounts_api()
    //     .derive_account_address_from_public_key(&parent_view_key.public_key)?;

    // let spend_key = wallet
    //     .sdk()
    //     .key_manager_api()
    //     .get_public_key(KeyBranch::Spend, key_id)?;
    let public_view_key = RistrettoPublicKeyBytes::from_bytes(
        RistrettoPublicKey::from_secret_key(&view_key).as_bytes(),
    )?;
    let new_account_address = wallet
        .sdk()
        .accounts_api()
        .derive_account_address_from_public_key(&public_view_key);
    // let spend_key =

    wallet.sdk().accounts_api().add_account(
        Some(&new_account_name),
        &new_account_address,
        new_key_id,
        KeyIdOrPublicKey::PublicKey(public_view_key),
        Epoch::zero(),
        false,
        false,
    )?;
    println!(
        "\n✓ Tapplet '{}' v{} installed successfully",
        manifest.name, manifest.version
    );

    Ok(())
}

/// Recursively copy a directory
fn copy_dir_recursive(src: &Path, dst: &Path) -> anyhow::Result<()> {
    if !dst.exists() {
        std::fs::create_dir_all(dst)?;
    }

    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name();
        let dst_path = dst.join(&file_name);

        // Skip .git directories
        if file_name == ".git" {
            continue;
        }

        if path.is_dir() {
            copy_dir_recursive(&path, &dst_path)?;
        } else {
            std::fs::copy(&path, &dst_path)?;
        }
    }

    Ok(())
}
