// Copyright 2025 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

mod macros;
mod spinner;
mod store;
mod table;

use crate::spinner::spinner;
use crate::store::{AccountRecord, WalletStore};
use crate::table::Table;
use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use ootle_rs::builtin_templates::UnsignedTransactionBuilder;
use ootle_rs::builtin_templates::account::IAccount;
use ootle_rs::builtin_templates::faucet::IFaucet;
use ootle_rs::key_provider::PrivateKeyProvider;
use ootle_rs::keys::OotleSecretKey;
use ootle_rs::provider::{
    IndexerProvider, PendingTransactionError, ProviderBuilder, WalletProvider,
};
use ootle_rs::wallet::{NoWallet, OotleWallet};
use ootle_rs::{Address, Network, ToAccountAddress, TransactionOutcome, TransactionRequest};
use std::path::Path;
use std::time::Duration;
use tari_template_lib_types::Amount;
use tari_template_lib_types::constants::{TARI_TOKEN, XTR_FAUCET_AMOUNT};
use termimad::crossterm::style::Color;
use url::Url;

const ANSI_GREEN: Color = Color::AnsiValue(2);
const ANSI_YELLOW: Color = Color::AnsiValue(3);
const ANSI_BLUE: Color = Color::AnsiValue(4);
const ANSI_WHITE: Color = Color::AnsiValue(15);

const DEFAULT_FEE: u64 = 1_000;
const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(120);

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
    #[arg(
        short = 'd',
        long,
        help = "Path to the database file",
        env = "OOTLE_DB_PATH",
        default_value = "data/wallet.sqlite"
    )]
    pub database_file: Box<Path>,
    #[arg(
        short = 'i',
        long,
        env = "OOTLE_INDEXER_URL",
        help = "URL of an Ootle indexer API. Defaults to a known indexer for the selected network"
    )]
    pub indexer_url: Option<Url>,
    #[arg(
        short = 'n',
        long,
        default_value = "esmeralda",
        env = "OOTLE_NETWORK",
        help = "Network to use (mainnet, esmeralda, localnet, etc)"
    )]
    pub network: Network,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new account, fund it with testnet funds (if applicable) and output the
    /// account and view secret keys
    CreateAccount {
        #[arg(short, long, help = "Name of the new account")]
        name: String,
        #[arg(
            short = 's',
            long,
            default_value_t = true,
            help = "Set the new account as the default account"
        )]
        set_default: bool,
        #[arg(
            short = 'o',
            long,
            help = "Also write the account details (including secret keys) to this JSON file"
        )]
        output_path: Option<Box<Path>>,
        #[arg(long, help = "Do not request testnet funds for the new account")]
        no_fund: bool,
        #[arg(
            short = 'f',
            long,
            default_value_t = DEFAULT_FEE,
            help = "Max fee to pay for the faucet transaction (in micro XTR)"
        )]
        fee_amount: u64,
    },
    /// List the accounts in the wallet
    #[clap(alias = "accounts")]
    ListAccounts,
    /// Show the keys of an account, including the secret account and view keys
    ShowKeys {
        #[arg(short, long, help = "Account name. Defaults to the default account")]
        account_name: Option<String>,
    },
    /// Set the default account
    SetDefaultAccount {
        #[arg(short, long, help = "Name of the account to set as default")]
        name: String,
    },
    /// Request testnet funds from the faucet
    #[clap(alias = "get-faucet-coins")]
    Faucet {
        #[arg(short, long, help = "Account name. Defaults to the default account")]
        account_name: Option<String>,
        #[arg(
            short = 'f',
            long,
            default_value_t = DEFAULT_FEE,
            help = "Max fee to pay for the faucet transaction (in micro XTR)"
        )]
        fee_amount: u64,
    },
    /// Show account balances
    Balance {
        #[arg(short, long, help = "Account name. Defaults to the default account")]
        account_name: Option<String>,
        #[arg(
            long,
            help = "Address to show balances for, instead of a wallet account",
            conflicts_with = "account_name"
        )]
        address: Option<Address>,
    },
    /// Transfer funds to another account (public transfer)
    Transfer {
        #[arg(
            short = 's',
            long,
            help = "The source account name. Defaults to the default account"
        )]
        from_account: Option<String>,
        #[arg(short = 't', long, help = "The destination address")]
        to_address: Address,
        #[arg(short = 'a', long, help = "The amount to transfer (in micro XTR)")]
        amount: u64,
        #[arg(
            short = 'f',
            long,
            default_value_t = DEFAULT_FEE,
            help = "Max fee to pay for the transfer (in micro XTR)"
        )]
        fee_amount: u64,
    },
    /// Show the transaction history recorded by this wallet
    History {
        #[arg(short, long, help = "Only show transactions for this account")]
        account_name: Option<String>,
    },
    /// Show wallet info
    ShowInfo,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let cli = Cli::parse();

    let mut store =
        WalletStore::open(&cli.common.database_file).context("Failed to open wallet database")?;

    match cli.command {
        Command::ShowInfo => {
            cli_println!("Ootle Wallet CLI");
            cli_println!("================");
            cli_println!(White, "Network: {}", cli.common.network);
            cli_println!(White, "Database: {}", cli.common.database_file.display());
            cli_println!(White, "Indexer URL: {}", resolve_indexer_url(&cli.common)?);
            cli_println!(White, "Accounts: {}", store.count_accounts()?);
            cli_println!("================");
        }
        Command::CreateAccount {
            name,
            set_default,
            output_path,
            no_fund,
            fee_amount,
        } => {
            let secret = OotleSecretKey::random(cli.common.network);
            let account = store.insert_account(&name, &secret, set_default)?;

            cli_println!(ANSI_GREEN, "✔️ Account '{}' created successfully", name);
            print_account_keys(&account);
            cli_println!(
                ANSI_YELLOW,
                "⚠️ Keep the secret keys safe. Anyone with the secret account key can spend your funds."
            );

            if let Some(path) = output_path {
                write_to_json_file(&account, &path)
                    .context("failed to write account details to file")?;
                cli_println!(ANSI_WHITE, "Account details written to {}", path.display());
            }

            if no_fund {
                return Ok(());
            }
            if !cli.common.network.is_testnet() {
                cli_println!(
                    ANSI_WHITE,
                    "ℹ️ There is no faucet on {}. Skipping funding.",
                    cli.common.network
                );
                return Ok(());
            }

            let mut provider = connect_with_wallet(&cli.common, secret).await?;
            request_faucet_funds(&mut provider, &store, &account, fee_amount).await?;
        }
        Command::ListAccounts => {
            let accounts = store.list_accounts()?;
            if accounts.is_empty() {
                cli_println!(
                    ANSI_WHITE,
                    "No accounts in the wallet. Create one with `create-account`"
                );
                return Ok(());
            }
            let mut table = Table::new();
            table.set_titles(vec!["Name", "Network", "Address", "Default"]);
            for account in accounts {
                table.add_row(table_row![
                    account.name,
                    account.network,
                    account.address,
                    if account.is_default { "✔" } else { "" }
                ]);
            }
            table.print_stdout();
        }
        Command::ShowKeys { account_name } => {
            let account = store.get_account(account_name.as_deref())?;
            print_account_keys(&account);
            cli_println!(
                ANSI_YELLOW,
                "⚠️ Keep the secret keys safe. Anyone with the secret account key can spend your funds."
            );
        }
        Command::SetDefaultAccount { name } => {
            store.set_default_account(&name)?;
            cli_println!(
                ANSI_GREEN,
                "✔️ Account '{}' is now the default account",
                name
            );
        }
        Command::Faucet {
            account_name,
            fee_amount,
        } => {
            if !cli.common.network.is_testnet() {
                bail!("There is no faucet on {}", cli.common.network);
            }
            let account = store.get_account(account_name.as_deref())?;
            let secret = load_secret(&cli.common, &account)?;
            let mut provider = connect_with_wallet(&cli.common, secret).await?;
            request_faucet_funds(&mut provider, &store, &account, fee_amount).await?;
        }
        Command::Balance {
            account_name,
            address,
        } => {
            let address = match address {
                Some(address) => address,
                None => {
                    let account = store.get_account(account_name.as_deref())?;
                    account.address.parse().map_err(|e| {
                        anyhow::anyhow!("invalid address in account '{}': {e}", account.name)
                    })?
                }
            };
            show_balances(&cli.common, &address).await?;
        }
        Command::Transfer {
            from_account,
            to_address,
            amount,
            fee_amount,
        } => {
            if amount == 0 {
                bail!("Transfer amount must be greater than zero");
            }
            if to_address.network() != cli.common.network {
                bail!(
                    "Destination address is for network {}, but {} was selected",
                    to_address.network(),
                    cli.common.network
                );
            }
            let account = store.get_account(from_account.as_deref())?;
            let secret = load_secret(&cli.common, &account)?;
            let mut provider = connect_with_wallet(&cli.common, secret).await?;
            transfer(
                &mut provider,
                &store,
                &account,
                &to_address,
                amount,
                fee_amount,
            )
            .await?;
        }
        Command::History { account_name } => {
            let transactions = store.list_transactions(account_name.as_deref())?;
            if transactions.is_empty() {
                cli_println!(ANSI_WHITE, "No transactions recorded");
                return Ok(());
            }
            let mut table = Table::new();
            table.set_titles(vec![
                "Transaction",
                "Account",
                "Kind",
                "Status",
                "Details",
                "Time",
            ]);
            for tx in transactions {
                table.add_row(table_row![
                    tx.transaction_id,
                    tx.account_name,
                    tx.kind,
                    tx.status,
                    tx.details,
                    tx.created_at
                ]);
            }
            table.print_stdout();
        }
    }

    Ok(())
}

fn print_account_keys(account: &AccountRecord) {
    cli_println!(ANSI_BLUE, "-----------------------------------");
    cli_println!(ANSI_WHITE, "Name: {}", account.name);
    cli_println!(ANSI_WHITE, "Network: {}", account.network);
    cli_println!(ANSI_WHITE, "Address: {}", account.address);
    cli_println!(
        ANSI_WHITE,
        "Component: {}",
        account.account_component_address
    );
    cli_println!(
        ANSI_WHITE,
        "Account public key: {}",
        account.account_public_key
    );
    cli_println!(ANSI_WHITE, "View public key: {}", account.view_public_key);
    cli_println!(
        ANSI_WHITE,
        "Secret account key: {}",
        account.account_secret_key
    );
    cli_println!(ANSI_WHITE, "Secret view key: {}", account.view_secret_key);
    cli_println!(ANSI_BLUE, "-----------------------------------");
}

/// Requests the fixed faucet amount, creating the on-chain account component if it does not
/// exist yet. The fee is paid from the freshly received faucet funds, so a brand-new account
/// needs no prior balance.
async fn request_faucet_funds(
    provider: &mut IndexerProvider<OotleWallet>,
    store: &WalletStore,
    account: &AccountRecord,
    fee_amount: u64,
) -> anyhow::Result<()> {
    let unsigned = IFaucet::new(provider)
        .take_faucet_funds()
        .pay_fee(fee_amount)
        .prepare()
        .await
        .context("failed to prepare faucet transaction")?;

    let transaction = TransactionRequest::new()
        .with_transaction(unsigned)
        .build(provider.wallet())
        .await
        .context("failed to sign faucet transaction")?;

    let pending = provider
        .send_transaction(transaction)
        .await
        .context("failed to submit faucet transaction")?;
    let tx_id = pending.tx_id();

    let outcome = spinner(
        format!("🤑 Requesting testnet funds (transaction {tx_id})..."),
        pending.watch(),
        |mut spinner, result| match result {
            Ok(outcome) => {
                spinner.stop_and_persist("✔️", format!("Transaction {tx_id} finalized"));
                Ok(outcome)
            }
            Err(err) => {
                spinner.stop_and_persist("❌", format!("Transaction {tx_id} failed"));
                Err(err)
            }
        },
    )
    .await;

    let details = format!(
        "{} XTR from faucet",
        Amount::from(XTR_FAUCET_AMOUNT).to_decimal_string(6)
    );
    record_outcome(
        store,
        &tx_id.to_string(),
        &account.name,
        "faucet",
        &details,
        &outcome,
    );
    check_watch_result(outcome)?;
    cli_println!(
        ANSI_GREEN,
        "✔️ Account '{}' funded with {} XTR from the testnet faucet",
        account.name,
        Amount::from(XTR_FAUCET_AMOUNT).to_decimal_string(6)
    );
    Ok(())
}

async fn transfer(
    provider: &mut IndexerProvider<OotleWallet>,
    store: &WalletStore,
    account: &AccountRecord,
    to_address: &Address,
    amount: u64,
    fee_amount: u64,
) -> anyhow::Result<()> {
    let unsigned = IAccount::new(provider)
        .pay_fee(fee_amount)
        .public_transfer(to_address, TARI_TOKEN, amount)
        .prepare()
        .await
        .context("failed to prepare transfer transaction")?;

    let transaction = TransactionRequest::new()
        .with_transaction(unsigned)
        .build(provider.wallet())
        .await
        .context("failed to sign transfer transaction")?;

    let pending = provider
        .send_transaction(transaction)
        .await
        .context("failed to submit transfer transaction")?;
    let tx_id = pending.tx_id();

    let outcome = spinner(
        format!("Submitting transaction {tx_id}..."),
        pending.watch(),
        |mut spinner, result| match result {
            Ok(outcome) => {
                spinner.stop_and_persist("✔️", format!("Transaction {tx_id} finalized"));
                Ok(outcome)
            }
            Err(err) => {
                spinner.stop_and_persist("❌", format!("Transaction {tx_id} failed"));
                Err(err)
            }
        },
    )
    .await;

    let details = format!(
        "{} XTR to {}",
        Amount::from(amount).to_decimal_string(6),
        to_address
    );
    record_outcome(
        store,
        &tx_id.to_string(),
        &account.name,
        "transfer",
        &details,
        &outcome,
    );
    check_watch_result(outcome)?;
    cli_println!(
        ANSI_GREEN,
        "✔️ Transferred {} XTR to {}",
        Amount::from(amount).to_decimal_string(6),
        to_address
    );
    Ok(())
}

async fn show_balances(common: &CommonArgs, address: &Address) -> anyhow::Result<()> {
    let component_address = address.to_account_address();
    let provider = connect_readonly(common).await?;

    if provider.get_substate(component_address).await?.is_none() {
        cli_println!(
            ANSI_WHITE,
            "Account {} is not on-chain yet. Fund it to create it.",
            component_address
        );
        return Ok(());
    }

    let balances = provider
        .get_account_balances(component_address)
        .await
        .context("failed to fetch account balances")?;

    cli_println!(ANSI_BLUE, "Balances for account:");
    cli_println!(ANSI_BLUE, "-----------------------------------");
    cli_println!(ANSI_WHITE, "Address: {}", address);
    cli_println!(ANSI_WHITE, "Component: {}", component_address);
    cli_println!(ANSI_BLUE, "-----------------------------------");
    cli_println!();

    let mut table = Table::new();
    table.set_titles(vec!["Resource", "Balance"]);
    for (resource_address, balance) in balances {
        let (symbol, divisibility) = if resource_address == TARI_TOKEN {
            // The TARI token is built-in and has no fetchable resource substate
            ("XTR".to_string(), 6)
        } else {
            // Fetch the resource for its symbol and divisibility. Fall back to raw values if
            // the resource cannot be fetched.
            let resource = provider
                .get_substate(resource_address)
                .await
                .ok()
                .flatten()
                .and_then(|s| s.into_substate_value().into_resource());
            let symbol = resource
                .as_ref()
                .and_then(|r| r.token_symbol().map(|s| s.to_owned()))
                .unwrap_or_else(|| resource_address.to_string());
            let divisibility = resource.as_ref().map(|r| r.divisibility()).unwrap_or(0);
            (symbol, divisibility)
        };
        table.add_row(table_row![
            symbol,
            balance.to_decimal_string(divisibility.into())
        ]);
    }
    table.print_stdout();
    Ok(())
}

fn load_secret(common: &CommonArgs, account: &AccountRecord) -> anyhow::Result<OotleSecretKey> {
    let secret = account.to_secret_key()?;
    if secret.network() != common.network {
        bail!(
            "Account '{}' is for network {}, but {} was selected",
            account.name,
            secret.network(),
            common.network
        );
    }
    Ok(secret)
}

fn record_outcome(
    store: &WalletStore,
    tx_id: &str,
    account_name: &str,
    kind: &str,
    details: &str,
    outcome: &Result<TransactionOutcome, PendingTransactionError>,
) {
    let status = match outcome {
        Ok(TransactionOutcome::Commit) => "committed",
        Ok(TransactionOutcome::OnlyFeeCommit(_)) => "fee-only",
        Ok(TransactionOutcome::Reject(_)) => "rejected",
        Err(PendingTransactionError::Timeout { .. }) => "timeout",
        Err(_) => "failed",
    };
    if let Err(err) = store.record_transaction(tx_id, account_name, kind, status, details) {
        log::warn!("Failed to record transaction {tx_id} in the wallet database: {err}");
    }
}

/// Converts a watch result into a final pass/fail, with a friendlier message for timeouts:
/// a timed-out transaction may still finalize later.
fn check_watch_result(
    result: Result<TransactionOutcome, PendingTransactionError>,
) -> anyhow::Result<()> {
    match result {
        Ok(TransactionOutcome::Commit) => Ok(()),
        Ok(TransactionOutcome::OnlyFeeCommit(reason)) => {
            bail!("Transaction failed (fees were charged): {reason}")
        }
        Ok(TransactionOutcome::Reject(reason)) => bail!("Transaction was rejected: {reason}"),
        Err(PendingTransactionError::Timeout { tx_id }) => bail!(
            "Timed out waiting for transaction {tx_id} to finalize. It may still complete - \
             check `balance` in a little while"
        ),
        Err(err) => Err(err).context("failed waiting for the transaction to finalize"),
    }
}

async fn connect_with_wallet(
    common: &CommonArgs,
    secret: OotleSecretKey,
) -> anyhow::Result<IndexerProvider<OotleWallet>> {
    let url = resolve_indexer_url(common)?;
    let wallet = OotleWallet::new(PrivateKeyProvider::new(secret));
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_with_transaction_timeout(&url, TRANSACTION_TIMEOUT)
        .await
        .with_context(|| format!("failed to connect to indexer at {url}"))?;
    check_indexer_network(&provider, common.network, &url).await?;
    Ok(provider)
}

async fn connect_readonly(common: &CommonArgs) -> anyhow::Result<IndexerProvider<NoWallet>> {
    let url = resolve_indexer_url(common)?;
    let provider = ProviderBuilder::new()
        .with_network(common.network)
        .connect(&url)
        .await
        .with_context(|| format!("failed to connect to indexer at {url}"))?;
    check_indexer_network(&provider, common.network, &url).await?;
    Ok(provider)
}

async fn check_indexer_network<W>(
    provider: &IndexerProvider<W>,
    expected: Network,
    url: &str,
) -> anyhow::Result<()> {
    let actual = provider
        .get_network()
        .await
        .with_context(|| format!("failed to connect to indexer at {url}"))?;
    if actual != expected {
        bail!("Indexer at {url} is on network {actual}, but {expected} was selected");
    }
    Ok(())
}

fn resolve_indexer_url(common: &CommonArgs) -> anyhow::Result<String> {
    if let Some(url) = &common.indexer_url {
        return Ok(url.to_string());
    }
    match common.network {
        Network::LocalNet | Network::Esmeralda => {
            Ok(ootle_rs::default_indexer_url(common.network).to_string())
        }
        network => {
            bail!("There is no default indexer URL for {network}. Specify one with --indexer-url")
        }
    }
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
