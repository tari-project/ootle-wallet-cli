// Copyright 2025 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

mod macros;
mod models;
mod spinner;
mod table;
mod transfer;
mod wallet;

use crate::spinner::spinner;
use crate::table::Table;
use crate::transfer::{handle_transfer_command, TransferCommand};
use crate::wallet::{BalanceStuff, Sdk, Wallet};
use anyhow::Context;
use clap::{Parser, Subcommand};
use std::path::Path;
use tari_crypto::ristretto::RistrettoSecretKey;
use tari_crypto::tari_utilities::hex::from_hex;
use tari_crypto::tari_utilities::{ByteArray, SafePassword};
use tari_engine_types::template_lib_models::ResourceAddress;
use tari_ootle_common_types::displayable::Displayable;
use tari_ootle_common_types::Network;
use tari_ootle_wallet_sdk_services::indexer_rest_api::IndexerRestApiNetworkInterface;
use tari_ootle_wallet_storage_sqlite::SqliteWalletStore;
use tari_template_lib_types::crypto::RistrettoPublicKeyBytes;
use termimad::crossterm::style::Color;
use url::Url;
use zeroize::Zeroizing;

const ANSI_GREEN: Color = Color::AnsiValue(2);
const ANSI_BLUE: Color = Color::AnsiValue(4);
const ANSI_WHITE: Color = Color::AnsiValue(15);

#[derive(Parser)]
#[command(name = "ootle", about = "Ootle wallet CLI")]
struct Cli {
    #[command(flatten)]
    common: CommonArgs,
    #[command(subcommand)]
    command: Command,
}

#[derive(Parser)]
struct CommonArgs {
    #[arg(short = 'p', long, help = "Password to decrypt the wallet file")]
    pub password: SafePassword,
    #[arg(
        short = 'd',
        long,
        help = "Path to the database file",
        default_value = "data/wallet.sqlite"
    )]
    pub database_file: Box<Path>,
    #[arg(
        short = 'i',
        long,
        default_value = "http://18.217.22.26:12500/json_rpc",
        help = "URL of an Ootle indexer API"
    )]
    pub indexer_url: Url,
    #[arg(
        short = 'n',
        long,
        default_value = "MainNet",
        help = "Network to use (mainnet, igor, localnet, etc)"
    )]
    pub network: Network,
}

#[derive(Subcommand)]
enum Command {
    /// Scan the blockchain for transactions
    Scan {
        #[arg(
            short,
            long,
            help = "Optional account name to scan. If not provided, all accounts will be used"
        )]
        account_name: Option<Box<str>>,
    },
    AddResource {
        #[arg(
            short,
            long,
            alias = "address",
            help = "The resource address in hex format"
        )]
        resource_address: ResourceAddress,
        #[arg(
            short = 'a',
            long,
            help = "Optional account name to add the resource to. If not provided, the default account will be used"
        )]
        account_name: Option<Box<str>>,
    },
    /// Show wallet balance
    Balance {
        #[arg(
            short,
            long,
            help = "Optional account name to show balance for. If not provided, all accounts will be used"
        )]
        account_name: Option<String>,
    },
    /// Import a wallet from a view key
    ImportViewKey {
        #[arg(short, long, alias = "view_key", help = "The view key in hex format")]
        view_private_key: Zeroizing<String>,
        #[arg(
            short,
            long,
            alias = "spend_key",
            help = "The spend public key in hex format"
        )]
        spend_public_key: RistrettoPublicKeyBytes,
    },
    CreateAccount {
        #[arg(short, long, help = "Name of the new account")]
        name: String,
        #[arg(
            short = 's',
            long,
            default_value_t = true,
            help = "Set the new account as active"
        )]
        set_active: bool,
        #[arg(
            short = 'o',
            long,
            help = "Output file to save the account details as JSON"
        )]
        output_path: Option<Box<Path>>,
    },
    #[clap(subcommand)]
    Transfer(TransferCommand),
    /// Create new seed words
    CreateSeedWords,
    /// Show wallet info
    ShowInfo,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let cli = Cli::parse();

    let mut wallet = init_wallet(&cli.common).context("Failed to initialize wallet SDK")?;

    match cli.command {
        Command::ShowInfo => {
            cli_println!("Ootle Wallet CLI");
            cli_println!("================");
            cli_println!(White, "Network: {}", wallet.network());
            cli_println!(White, "Database: {}", cli.common.database_file.display());
            cli_println!(White, "Indexer URL: {}", cli.common.indexer_url);
            cli_println!("================");
        }
        Command::ImportViewKey {
            view_private_key,
            spend_public_key,
        } => {
            let view_private_key =
                Zeroizing::new(from_hex(&view_private_key).context("Invalid view private key")?);
            let view_private_key = RistrettoSecretKey::from_canonical_bytes(&view_private_key)
                .context("Invalid view private key")?;

            wallet.import_view_only_account(
                &spend_public_key.to_string(),
                &view_private_key,
                spend_public_key,
            )?;
            cli_println!(
                ANSI_GREEN,
                "✔️ View-only account {} imported successfully",
                spend_public_key
            );
        }
        Command::AddResource {
            resource_address,
            account_name,
        } => {
            let account = wallet.get_account_or_default(account_name.as_deref())?; // Validate account exists

            wallet
                .sdk()
                .accounts_api()
                .associate_stealth_resource(account.component_address(), resource_address)?;
            cli_println!(
                ANSI_GREEN,
                "✔️ Resource {} added to account '{}'",
                resource_address,
                account.account().name.as_deref().unwrap_or("<unnamed>")
            );
        }
        Command::Scan { account_name } => {
            // This is mainly to check that the user set a working URL
            wallet
                .check_indexer_connection()
                .await
                .context("indexer connection failed")?;
            cli_println!(ANSI_GREEN, "✔️ Connected to indexer");

            let account = wallet.get_account_or_default(account_name.as_deref())?; // Validate account exists
            let component_address = *account.component_address();
            spinner(
                format!(
                    "Refreshing account {}... This may take a while.",
                    component_address
                ),
                wallet.refresh_account(component_address),
                |mut spinner, result| match result {
                    Ok(true) => {
                        spinner.stop_and_persist(
                            "✔️",
                            format!(
                                "Account {} refreshed and found balance updates",
                                component_address
                            ),
                        );
                    }
                    Ok(false) => {
                        spinner.stop_and_persist(
                            "✔️",
                            format!("Account {} refreshed. No changes.", component_address),
                        );
                    }
                    Err(err) => {
                        spinner.stop_and_persist(
                            "❌",
                            format!(
                                "Failed to refresh account: {err}. Will display last known balances"
                            ),
                        );
                    }
                },
            )
            .await;
            spinner(
                "Waiting for scanning to complete... This may take a while.",
                wallet.scan_for_utxos(account),
                |mut spinner, res| match res {
                    Ok(_) => {
                        spinner.stop_and_persist("✔️", "UTXO Scanning - Done".to_string());
                    }
                    Err(err) => {
                        spinner.stop_and_persist("❌", format!("UTXO Scanning failed: {err}"));
                    }
                },
            )
            .await;

            let events = wallet.drain_events();
            cli_println!(ANSI_BLUE, "Events:");
            if events.is_empty() {
                cli_println!(ANSI_WHITE, "No events");
            } else {
                for event in events {
                    cli_println!(ANSI_WHITE, "   - {:?}", event);
                }
            }
        }
        Command::Balance { account_name } => {
            let account = match account_name {
                Some(name) => wallet.sdk().accounts_api().get_account_by_name(&name)?,
                None => wallet.sdk().accounts_api().get_default()?,
            };
            let BalanceStuff { balances, memos } =
                wallet.get_balances_for_account(account.component_address())?;
            cli_println!(
                Blue,
                "Balances for account '{}':",
                account.account().name.as_deref().unwrap_or("<unnamed>")
            );

            cli_println!(ANSI_BLUE, "-----------------------------------");
            cli_println!(ANSI_WHITE, "Address: {}", account.address());
            cli_println!(ANSI_WHITE, "Component: {}", account.component_address());
            cli_println!(ANSI_WHITE, "Public Key: {}", account.owner_public_key());
            cli_println!(ANSI_BLUE, "-----------------------------------");
            cli_println!();

            let mut table = Table::new();
            table.set_titles(vec![
                "Resource",
                "Balance",
                "Pvt Balance",
                "#UTXOs",
                "Type",
                "Vault",
            ]);

            for balance in balances {
                table.add_row(table_row![
                    balance
                        .token_symbol
                        .unwrap_or_else(|| balance.resource_address.to_string()),
                    balance
                        .balance
                        .to_decimal_string(balance.divisibility.into()),
                    balance
                        .confidential_balance
                        .to_decimal_string(balance.divisibility.into()),
                    balance.num_outputs,
                    balance.resource_type,
                    balance.vault_address.display(),
                ]);
            }
            table.print_stdout();

            if !memos.is_empty() {
                cli_println!();
                cli_println!(ANSI_BLUE, "Memos:");
                let mut table = Table::new();
                table.set_titles(vec!["Utxo", "Message"]);

                for (commitment, memo) in memos {
                    let Some(message) = memo.as_message() else {
                        continue;
                    };
                    table.add_row(table_row![commitment, message]);
                }
                table.print_stdout();
            }
        }
        Command::CreateSeedWords => {
            let seed_words = wallet.create_seed_words()?;
            cli_println!(ANSI_GREEN, "✔️ Seed words created successfully");
            cli_println!(ANSI_WHITE, "{}", seed_words.join(" ").reveal());
        }
        Command::CreateAccount {
            name,
            set_active,
            output_path,
        } => {
            let account = wallet.create_account(&name, set_active)?;
            cli_println!(ANSI_GREEN, "✔️ Account '{}' created successfully", name);
            let json = serde_json::json!({
                "component_address": account.component_address(),
                "address": account.address(),
                "account_public_key": account.owner_public_key(),
                "key_index": account.owner_key_id(),
                "name": name,
            });
            cli_println!(ANSI_WHITE, "{:#}", json);
            if let Some(path) = output_path {
                write_to_json_file(&json, path.as_ref())
                    .context("failed to write account details to file")?;
                cli_println!(ANSI_WHITE, "Account details written to {}", path.display());
            }
        }
        Command::Transfer(command) => {
            handle_transfer_command(&mut wallet, command).await?;
        }
    }

    Ok(())
}

fn write_to_json_file<T: serde::Serialize, P: AsRef<Path>>(
    data: &T,
    path: P,
) -> anyhow::Result<()> {
    let mut file = std::fs::File::options()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .context("failed to open file for writing")?;
    serde_json::to_writer_pretty(&mut file, data).context("failed to encode data to file")?;
    Ok(())
}

fn init_wallet(common: &CommonArgs) -> anyhow::Result<Wallet> {
    let store = SqliteWalletStore::try_open(&common.database_file)?;
    store.run_migrations()?;
    let indexer = IndexerRestApiNetworkInterface::new(common.indexer_url.clone());
    let config = tari_ootle_wallet_sdk::WalletSdkConfig {
        network: common.network,
        override_keyring_password: Some(common.password.clone()),
    };

    let mut sdk = Sdk::initialize(store, indexer, config)?;
    // Load seed words if present. If we don't do this then the wallet will be in read-only mode
    if sdk.load_seed_words()?.is_some() {
        cli_println!(ANSI_BLUE, "✔️ Wallet is in read/write mode");
    } else {
        cli_println!(ANSI_GREEN, "✔️ Wallet is in read-only mode");
    }
    Ok(Wallet::new(sdk))
}
