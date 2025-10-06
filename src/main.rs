// Copyright 2025 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

mod macros;
mod models;
mod spinner;
mod table;
mod wallet;

use crate::spinner::spinner;
use crate::table::Table;
use crate::wallet::Wallet;
use anyhow::Context;
use clap::{Parser, Subcommand};
use std::path::Path;
use tari_crypto::ristretto::RistrettoSecretKey;
use tari_crypto::tari_utilities::hex::from_hex;
use tari_crypto::tari_utilities::{ByteArray, SafePassword};
use tari_engine_types::template_lib_models::ResourceAddress;
use tari_ootle_common_types::displayable::Displayable;
use tari_ootle_common_types::Network;
use tari_ootle_wallet_sdk::WalletSdk;
use tari_ootle_wallet_sdk_services::indexer_jrpc::IndexerJsonRpcNetworkInterface;
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
    command: Commands,
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
enum Commands {
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
    ShowInfo,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let cli = Cli::parse();

    let mut wallet = init_wallet(&cli.common).context("Failed to initialize wallet SDK")?;

    match cli.command {
        Commands::ShowInfo => {
            cli_println!("Ootle Wallet CLI");
            cli_println!("================");
            cli_println!(White, "Network: {}", wallet.network());
            cli_println!(White, "Database: {}", cli.common.database_file.display());
            cli_println!(White, "Indexer URL: {}", cli.common.indexer_url);
            cli_println!("================");
        }
        Commands::ImportViewKey {
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
        Commands::AddResource {
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
        Commands::Scan { account_name } => {
            // This is mainly to check that the user set a working URL
            wallet
                .check_indexer_connection()
                .await
                .context("indexer connection failed")?;
            cli_println!(ANSI_GREEN, "✔️ Connected to indexer");

            let account = wallet.get_account_or_default(account_name.as_deref())?; // Validate account exists
            let component_address = *account.component_address();
            spinner(
                "Refreshing account... This may take a while.",
                wallet.refresh_account(component_address),
                |mut spinner, result| match result {
                    Ok(true) => {
                        spinner.stop_and_persist(
                            "✔️",
                            "Account refreshed and found balance updates".to_string(),
                        );
                    }
                    Ok(false) => {
                        spinner
                            .stop_and_persist("✔️", "Account refreshed. No changes.".to_string());
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
                |mut spinner, _| {
                    spinner.stop_and_persist("✔️", "Scanning - Done".to_string());
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
        Commands::Balance { account_name } => {
            let account = match account_name {
                Some(name) => wallet.sdk().accounts_api().get_account_by_name(&name)?,
                None => wallet.sdk().accounts_api().get_default()?,
            };
            let balances = wallet.get_balances_for_account(account.component_address())?;
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
        }
    }

    Ok(())
}

fn init_wallet(common: &CommonArgs) -> anyhow::Result<Wallet> {
    let store = SqliteWalletStore::try_open(&common.database_file)?;
    store.run_migrations()?;
    let indexer = IndexerJsonRpcNetworkInterface::new(common.indexer_url.clone());
    let config = tari_ootle_wallet_sdk::WalletSdkConfig {
        network: common.network,
        override_keyring_password: Some(common.password.clone()),
    };

    let sdk = WalletSdk::initialize(store, indexer, config)?;
    Ok(Wallet::new(sdk))
}
