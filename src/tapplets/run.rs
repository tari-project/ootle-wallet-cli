// Copyright 2025 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use crate::wallet::{
    Sdk, Wallet, create_transfer, create_transfer_transaction, submit_transaction,
    wait_for_transaction_to_finalize,
};
use async_trait::async_trait;
use dialoguer::{Input, Select};
use log::info;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tari_engine_types::template_lib_models::ComponentAddress;
use tari_ootle_wallet_sdk::OotleAddress;
use tari_tapplet_lib::LuaTappletHost;
use tari_tapplet_lib::host::MinotariTappletApiV1;
use tokio::sync::RwLock;

/// Run an installed tapplet
pub async fn run_tapplet(
    wallet: &mut Wallet,
    name: &str,
    method: &str,
    args: HashMap<String, String>,
    cache_directory: &Path,
    account_name: Option<&str>,
) -> anyhow::Result<()> {
    let installed_dir = cache_directory.join("installed").join(name);

    if !installed_dir.exists() {
        anyhow::bail!(
            "Tapplet '{}' is not installed. Install it first with 'tapplet install'",
            name
        );
    }

    // Look for the main script/executable
    // Get the account to use
    let account = if let Some(name) = account_name {
        wallet.sdk().accounts_api().get_account_by_name(name)?
    } else {
        wallet.sdk().accounts_api().get_default()?
    };

    println!(
        "Running tapplet '{}' for account '{}'",
        name,
        account.account().name.as_deref().unwrap_or("<unnamed>")
    );
    println!("-----------------------------------");

    run_lua(
        // account.account().name.as_deref().unwrap_or("<unnamed>"),
        wallet.sdk().clone(),
        name,
        method,
        args,
        cache_directory.to_path_buf(),
    )
    .await?;

    // Set up environment variables for the tapplet

    // Wait for the process to complete

    // println!("-----------------------------------");
    // if status.success() {
    //     println!("✓ Tapplet '{}' completed successfully", name);
    //     Ok(())
    // } else {
    //     anyhow::bail!(
    //         "Tapplet '{}' failed with exit code: {}",
    //         name,
    //         status.code().unwrap_or(-1)
    //     )
    // }
    Ok(())
}

#[derive(Clone)]
struct OotleApiProvider {
    wallet: Arc<RwLock<Sdk>>,
    tapplet_data_address: OotleAddress,
    fee_amount: u64,
    account_address: ComponentAddress,
}

impl OotleApiProvider {
    pub async fn try_create(
        wallet: Sdk,
        tapplet_data_address: OotleAddress,
        fee_amount: u64,
        account_address: ComponentAddress,
    ) -> Result<Self, anyhow::Error> {
        // Initialize the API provider here
        Ok(Self {
            wallet: Arc::new(RwLock::new(wallet)),
            tapplet_data_address,
            fee_amount,
            account_address,
        })
    }
}

#[async_trait]
impl MinotariTappletApiV1 for OotleApiProvider {
    async fn append_data(&self, slot: &str, value: &str) -> Result<(), anyhow::Error> {
        let options = vec![
            "Allow this time",
            "Allow and remember my choice for this tapplet (Not implemented)",
            "Deny",
        ];
        let selection = Select::new()
        .with_prompt("Tapplet is trying to save data in a slot (by sending a transaction to itself). Allow?")
        .items(&options)
        .default(0)
        .interact()
        .unwrap();

        if selection == 2 {
            return Err(anyhow::anyhow!("User denied data append operation"));
        }
        if selection == 1 {
            return Err(anyhow::anyhow!("Remembering choice not implemented yet"));
        }

        let fees = Input::new()
            .with_prompt("Enter fee amount for the data append transaction")
            .default(self.fee_amount)
            .interact_text()
            .unwrap();

        let fee_amount: u64 = fees;

        let w = self.wallet.read().await;
        let message = format!(
            "t:\"{}\",\"{}\"",
            slot.replace("\"", "\"\""),
            value.replace("\"", "\"\"")
        );
        let transfer = create_transfer(
            &w,
            None,
            &self.tapplet_data_address,
            fee_amount,
            0,
            &[0],
            Some(&message),
        )?;
        let unsigned_tx = create_transfer_transaction(&w, w.network(), &transfer)?;

        let signed_tx = w.local_signer_api().sign(
            transfer.required_signer_key_branch,
            transfer.required_signer_key_id,
            unsigned_tx.authorized_sealed_signer().build(),
        )?;

        let id = submit_transaction(&w, signed_tx, None, Some(transfer.lock_id)).await?;
        info!("Appended data to slot '{}' in transaction {}", slot, id);

        wait_for_transaction_to_finalize(&w, id).await?;
        Ok(())
    }
    async fn load_data_entries(&self, slot: &str) -> Result<Vec<String>, anyhow::Error> {
        let w = self.wallet.read().await;
        let entries = w
            .stealth_outputs_api()
            .get_unspent_outputs_by_account(&self.account_address, false)?;
        let mut results = Vec::new();
        for entry in entries {
            if let Some(message) = entry
                .memo
                .and_then(|m| m.as_memo_message().map(|m| m.to_string()))
            {
                let prefix = format!("t:\"{}\",\"", slot.replace("\"", "\"\""));
                if message.starts_with(&prefix) {
                    let suffix = message.trim_start_matches(&prefix);
                    if let Some(end_idx) = suffix.find('"') {
                        let value = &suffix[..end_idx];
                        let value = value.replace("\"\"", "\"");
                        results.push(value);
                    }
                }
            }
        }
        Ok(results)
    }
}

pub async fn run_lua(
    wallet: Sdk,
    name: &str,
    method: &str,
    args: HashMap<String, String>,
    cache_directory: PathBuf,
) -> Result<(), anyhow::Error> {
    let installed_dir = cache_directory.join("installed");
    let tapplet_path = installed_dir.join(name);

    if !tapplet_path.exists() {
        println!("Tapplet '{}' is not installed.", name);
        return Err(anyhow::anyhow!("Tapplet not installed"));
    }
    let config = tari_tapplet_lib::parse_tapplet_file(tapplet_path.join("manifest.toml"))?;

    let tapplet_name = format!("tapplet_{}", config.public_key);
    let tapplet_account = wallet.accounts_api().get_account_by_name(&tapplet_name)?;

    let api = OotleApiProvider::try_create(
        wallet,
        tapplet_account.address.clone(),
        1,
        *tapplet_account.component_address(),
    )
    .await?;

    // Load the tapplet configuration
    let config = tari_tapplet_lib::parse_tapplet_file(tapplet_path.join("manifest.toml"))?;
    let lua_path = tapplet_path.join("main").with_extension("lua");

    let tapplet = LuaTappletHost::new(config, lua_path, api)?;

    println!("Running method '{}' on tapplet '{}'", method, name);

    // Convert HashMap to JSON Value
    let args_json: Value = serde_json::to_value(&args)?;

    let result = tapplet.run(method, args_json).await?;

    println!("\nResult:");
    print_value_as_table(&result, 0);

    Ok(())
}
fn print_value_as_table(value: &Value, indent: usize) {
    let prefix = "  ".repeat(indent);

    match value {
        Value::Object(map) => {
            for (key, val) in map {
                match val {
                    Value::Object(_) | Value::Array(_) => {
                        println!("{}{}", prefix, key);
                        print_value_as_table(val, indent + 1);
                    }
                    _ => {
                        println!("{}{}  {}", prefix, key, format_value(val));
                    }
                }
            }
        }
        Value::Array(arr) => {
            for (idx, val) in arr.iter().enumerate() {
                match val {
                    Value::Object(_) | Value::Array(_) => {
                        println!("{}[{}]", prefix, idx);
                        print_value_as_table(val, indent + 1);
                    }
                    _ => {
                        println!("{}[{}]  {}", prefix, idx, format_value(val));
                    }
                }
            }
        }
        _ => {
            println!("{}{}", prefix, format_value(value));
        }
    }
}
fn format_value(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        _ => value.to_string(),
    }
}
