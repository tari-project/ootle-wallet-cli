// Copyright 2025 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use super::default_registries::get_default_registries;
use super::search::TappletManifest;
use crate::wallet::Wallet;
use anyhow::{Context, anyhow};
use std::path::Path;

/// Install a tapplet from a registry
pub async fn install_from_registry(
    wallet: &mut Wallet,
    registry: Option<String>,
    name: &str,
    cache_directory: &Path,
    account_name: Option<&str>,
) -> anyhow::Result<()> {
    let default_registries = get_default_registries();

    // Find the tapplet in registries
    let mut found_manifest: Option<(String, TappletManifest, std::path::PathBuf)> = None;

    for (reg_name, _url) in default_registries {
        // Skip if specific registry requested and this isn't it
        if let Some(ref requested_registry) = registry {
            if reg_name != requested_registry {
                continue;
            }
        }

        let registry_dir = cache_directory.join("registries").join(reg_name);
        let tapplets_dir = registry_dir.join("tapplets");

        if !tapplets_dir.exists() {
            continue;
        }

        // Look for the tapplet
        for entry in std::fs::read_dir(&tapplets_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                let manifest_path = path.join("manifest.toml");
                if manifest_path.exists() {
                    let manifest_content = std::fs::read_to_string(&manifest_path)?;
                    if let Ok(manifest) = toml::from_str::<TappletManifest>(&manifest_content) {
                        if manifest.name == name {
                            found_manifest = Some((reg_name.to_string(), manifest, path));
                            break;
                        }
                    }
                }
            }
        }

        if found_manifest.is_some() {
            break;
        }
    }

    let (reg_name, manifest, tapplet_source_dir) =
        found_manifest.ok_or_else(|| anyhow!("Tapplet '{}' not found in registries", name))?;

    println!(
        "Found tapplet '{}' v{} in registry '{}'",
        manifest.name, manifest.version, reg_name
    );
    if let Some(desc) = &manifest.description {
        println!("Description: {}", desc);
    }
    if let Some(author) = &manifest.author {
        println!("Author: {}", author);
    }

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
    copy_dir_recursive(path, &installed_dir)?;

    // // Create child accounts for each parent account
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
