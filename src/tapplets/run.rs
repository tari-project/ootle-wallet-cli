// Copyright 2025 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use crate::wallet::Wallet;
use anyhow::{Context, anyhow};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tari_tapplet_lib::LuaTappletHost;
use tari_tapplet_lib::host::MinotariTappletApiV1;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

/// Run an installed tapplet
pub async fn run_tapplet(
    wallet: &Wallet,
    name: &str,
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
struct OotleApiProvider {}

impl OotleApiProvider {
    pub async fn try_create(// account_name: String,
        // config: &TappletManifest,
        // database_file: PathBuf,
        // password: String,
    ) -> Result<Self, anyhow::Error> {
        // Initialize the API provider here
        Ok(Self {})
    }
}

#[async_trait]
impl MinotariTappletApiV1 for OotleApiProvider {
    async fn append_data(&self, slot: &str, value: &str) -> Result<(), anyhow::Error> {
        todo!()
    }
    async fn load_data_entries(&self, slot: &str) -> Result<Vec<String>, anyhow::Error> {
        todo!()
    }
}

pub async fn run_lua(
    account_name: &str,
    database_file: &str,
    password: &str,
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

    let api = OotleApiProvider::try_create(
        // account_name.to_string(),
        // &config,
        // database_file.into(),
        // password.to_string(),
    )
    .await?;

    // Load the tapplet configuration
    let config = tari_tapplet_lib::parse_tapplet_file(tapplet_path.join("manifest.toml"))?;
    let lua_path = tapplet_path.join(&config.name).with_extension("lua");

    let mut tapplet = LuaTappletHost::new(config, lua_path, api)?;

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
