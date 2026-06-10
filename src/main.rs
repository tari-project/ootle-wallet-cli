// Copyright 2025 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

#[macro_use]
mod macros;
mod keys;
mod prompt;
mod spinner;
mod store;
mod table;

use crate::prompt::{prompt_line, prompt_new_passphrase, prompt_with_default, prompt_yes_no};
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
use tari_common_types::seeds::cipher_seed::CipherSeed;
use tari_common_types::seeds::mnemonic::{Mnemonic, MnemonicLanguage};
use tari_common_types::seeds::seed_words::SeedWords;
use tari_crypto::tari_utilities::hex::to_hex;
use tari_crypto::tari_utilities::{ByteArray, Hidden, SafePassword};
use tari_template_lib_types::Amount;
use tari_template_lib_types::constants::{TARI_TOKEN, XTR_FAUCET_AMOUNT};
use termimad::crossterm::style::Color;
use url::Url;
use zeroize::Zeroizing;

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
        global = true,
        help = "Path to the database file",
        env = "OOTLE_DB_PATH",
        default_value = "data/wallet.sqlite"
    )]
    pub database_file: Box<Path>,
    #[arg(
        short = 'i',
        long,
        global = true,
        env = "OOTLE_INDEXER_URL",
        help = "URL of an Ootle indexer API. Defaults to a known indexer for the wallet's network"
    )]
    pub indexer_url: Option<Url>,
    #[arg(
        short = 'n',
        long,
        env = "OOTLE_NETWORK",
        help = "Network to use during setup. After setup, the wallet's network is stored in the database"
    )]
    pub network: Option<Network>,
    #[arg(
        short = 'p',
        long,
        global = true,
        env = "OOTLE_PASSWORD",
        help = "Wallet passphrase. If not provided, you will be prompted when required"
    )]
    pub password: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the initial wallet setup: choose a network, create (or restore) the wallet seed
    /// words, create the first account and fund it on testnets
    Setup {
        #[arg(short, long, help = "Name of the first account")]
        account_name: Option<String>,
        #[arg(long, help = "Restore the wallet from existing seed words")]
        restore: bool,
        #[arg(long, help = "Do not request testnet funds for the first account")]
        no_fund: bool,
        #[arg(
            short = 'f',
            long,
            default_value_t = DEFAULT_FEE,
            help = "Max fee to pay for the faucet transaction (in micro XTR)"
        )]
        fee_amount: u64,
    },
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
            help = "Also write the account details (public keys and address) to this JSON file"
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
    /// Show the wallet seed words
    ShowSeedWords,
    /// Set the default account
    SetDefaultAccount {
        #[arg(short, long, help = "Name of the account to set as default")]
        name: String,
    },
    /// Change a wallet setting stored in the database
    Set {
        #[arg(value_enum, help = "The setting to change")]
        key: SettingKey,
        #[arg(help = "The new value. An empty value resets the setting to its default")]
        value: String,
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

#[derive(Clone, Copy, clap::ValueEnum)]
enum SettingKey {
    /// The network this wallet operates on
    Network,
    /// The Ootle indexer API URL
    IndexerUrl,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let cli = Cli::parse();

    let mut store =
        WalletStore::open(&cli.common.database_file).context("Failed to open wallet database")?;

    match cli.command {
        Command::ShowInfo => {
            let network = store.network()?;
            cli_println!("Ootle Wallet CLI");
            cli_println!("================");
            match network {
                Some(network) => {
                    cli_println!(White, "Network: {}", network);
                    match resolve_indexer_url(&cli.common, &store, network) {
                        Ok(url) => cli_println!(White, "Indexer URL: {}", url),
                        Err(_) => cli_println!(White, "Indexer URL: not set (use --indexer-url)"),
                    }
                }
                None => {
                    cli_println!(White, "Network: not set. Run `setup` first");
                }
            }
            cli_println!(White, "Database: {}", cli.common.database_file.display());
            cli_println!(White, "Accounts: {}", store.count_accounts()?);
            cli_println!("================");
        }
        Command::Setup {
            account_name,
            restore,
            no_fund,
            fee_amount,
        } => {
            setup(
                &cli.common,
                &mut store,
                account_name,
                restore,
                no_fund,
                fee_amount,
            )
            .await?;
        }
        Command::CreateAccount {
            name,
            set_default,
            output_path,
            no_fund,
            fee_amount,
        } => {
            let network = resolve_network(&cli.common, &store)?;
            let (seed, _) = load_cipher_seed(&cli.common, &store)?;
            let index = store.next_derivation_index()?;
            let secret = keys::derive_account_secret_key(&seed, network, index);
            let account = store.insert_account(&name, index, &secret.to_address(), set_default)?;

            cli_println!(ANSI_GREEN, "✔️ Account '{}' created successfully", name);
            print_account_keys(&account, &secret);
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
            if !network.is_testnet() {
                cli_println!(
                    ANSI_WHITE,
                    "ℹ️ There is no faucet on {}. Skipping funding.",
                    network
                );
                return Ok(());
            }

            let mut provider = connect_with_wallet(&cli.common, &store, network, secret).await?;
            request_faucet_funds(&mut provider, &store, &account, fee_amount).await?;
        }
        Command::ListAccounts => {
            let accounts = store.list_accounts()?;
            if accounts.is_empty() {
                cli_println!(ANSI_WHITE, "No accounts in the wallet. Run `setup` first");
                return Ok(());
            }
            let mut table = Table::new();
            table.set_titles(vec!["Name", "Address", "Default"]);
            for account in accounts {
                table.add_row(table_row![
                    account.name,
                    account.address,
                    if account.is_default { "✔" } else { "" }
                ]);
            }
            table.print_stdout();
        }
        Command::ShowKeys { account_name } => {
            let network = resolve_network(&cli.common, &store)?;
            let account = store.get_account(account_name.as_deref())?;
            let (seed, _) = load_cipher_seed(&cli.common, &store)?;
            let secret = keys::derive_account_secret_key(&seed, network, account.derivation_index);
            print_account_keys(&account, &secret);
            cli_println!(
                ANSI_YELLOW,
                "⚠️ Keep the secret keys safe. Anyone with the secret account key can spend your funds."
            );
        }
        Command::ShowSeedWords => {
            let (seed, passphrase) = load_cipher_seed(&cli.common, &store)?;
            let words = seed
                .to_mnemonic(MnemonicLanguage::English, passphrase)
                .map_err(|e| anyhow::anyhow!("failed to encode seed words: {e}"))?;
            cli_println!(ANSI_WHITE, "{}", words.join(" ").reveal());
            cli_println!(
                ANSI_YELLOW,
                "⚠️ Anyone with these seed words (and your passphrase, if set) can spend your funds."
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
        Command::Set { key, value } => match key {
            SettingKey::Network => {
                let network: Network = value
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid network '{value}': {e:?}"))?;
                store.set_network(network)?;
                // The account keys are network-independent, but the stored address
                // encodings include the network and must be rewritten
                store.update_account_addresses(network)?;
                cli_println!(ANSI_GREEN, "✔️ Network set to {}", network);
            }
            SettingKey::IndexerUrl => {
                if value.is_empty() {
                    store.clear_indexer_url()?;
                    cli_println!(ANSI_GREEN, "✔️ Indexer URL reset to the network default");
                } else {
                    let url: Url = value
                        .parse()
                        .with_context(|| format!("invalid indexer URL '{value}'"))?;
                    store.set_indexer_url(url.as_str())?;
                    cli_println!(ANSI_GREEN, "✔️ Indexer URL set to {}", url);
                }
            }
        },
        Command::Faucet {
            account_name,
            fee_amount,
        } => {
            let network = resolve_network(&cli.common, &store)?;
            if !network.is_testnet() {
                bail!("There is no faucet on {}", network);
            }
            let account = store.get_account(account_name.as_deref())?;
            let (seed, _) = load_cipher_seed(&cli.common, &store)?;
            let secret = keys::derive_account_secret_key(&seed, network, account.derivation_index);
            let mut provider = connect_with_wallet(&cli.common, &store, network, secret).await?;
            request_faucet_funds(&mut provider, &store, &account, fee_amount).await?;
        }
        Command::Balance {
            account_name,
            address,
        } => {
            // An address carries its own network, so it can be queried without a wallet
            let (address, network) = match address {
                Some(address) => {
                    let network = address.network();
                    (address, network)
                }
                None => {
                    let network = resolve_network(&cli.common, &store)?;
                    let account = store.get_account(account_name.as_deref())?;
                    let address = account.address.parse().map_err(|e| {
                        anyhow::anyhow!("invalid address in account '{}': {e}", account.name)
                    })?;
                    (address, network)
                }
            };
            show_balances(&cli.common, &store, network, &address).await?;
        }
        Command::Transfer {
            from_account,
            to_address,
            amount,
            fee_amount,
        } => {
            let network = resolve_network(&cli.common, &store)?;
            if amount == 0 {
                bail!("Transfer amount must be greater than zero");
            }
            if to_address.network() != network {
                bail!(
                    "Destination address is for network {}, but this wallet is on {}",
                    to_address.network(),
                    network
                );
            }
            let account = store.get_account(from_account.as_deref())?;
            let (seed, _) = load_cipher_seed(&cli.common, &store)?;
            let secret = keys::derive_account_secret_key(&seed, network, account.derivation_index);
            let mut provider = connect_with_wallet(&cli.common, &store, network, secret).await?;
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

async fn setup(
    common: &CommonArgs,
    store: &mut WalletStore,
    account_name: Option<String>,
    restore: bool,
    no_fund: bool,
    fee_amount: u64,
) -> anyhow::Result<()> {
    if store.is_initialized()? {
        bail!(
            "Wallet at {} is already set up. Use a different --database-file to create a new wallet",
            common.database_file.display()
        );
    }

    cli_println!(ANSI_BLUE, "Ootle wallet setup");
    cli_println!(ANSI_BLUE, "==================");

    let interactive = account_name.is_none();

    // 1. Network
    let network = match common.network {
        Some(network) => network,
        None => loop {
            let input = prompt_with_default(
                "Network (esmeralda, localnet, igor, nextnet, stagenet, mainnet)",
                "esmeralda",
            )?;
            match input.parse::<Network>() {
                Ok(network) => break network,
                Err(e) => cli_println!(ANSI_YELLOW, "{:?}", e),
            }
        },
    };

    // 2. Indexer API URL
    let indexer_url = match (
        common.indexer_url.as_ref(),
        known_default_indexer_url(network),
    ) {
        (Some(url), _) => url.to_string(),
        (None, default) if interactive => loop {
            let input = match default {
                Some(default) => prompt_with_default("Indexer API URL", default)?,
                None => prompt_line("Indexer API URL: ")?,
            };
            if input.is_empty() {
                cli_println!(ANSI_YELLOW, "An indexer URL is required for {}", network);
                continue;
            }
            match input.parse::<Url>() {
                Ok(url) => break url.to_string(),
                Err(e) => cli_println!(ANSI_YELLOW, "Invalid URL: {}", e),
            }
        },
        (None, Some(default)) => default.to_string(),
        (None, None) => {
            bail!("There is no default indexer URL for {network}. Provide one with --indexer-url")
        }
    };

    // 3. Optional passphrase protecting the seed
    let passphrase = match common.password.as_ref() {
        Some(p) => Some(SafePassword::from(p.clone())),
        None => prompt_new_passphrase()?.map(|p| SafePassword::from(p.to_string())),
    };

    // 4. Create or restore the seed
    let seed = if restore {
        let words_line =
            Zeroizing::new(prompt_line("Enter your seed words separated by spaces: ")?);
        let words = SeedWords::new(
            words_line
                .split_whitespace()
                .map(|w| Hidden::hide(w.to_string()))
                .collect(),
        );
        CipherSeed::from_mnemonic(&words, passphrase.clone()).map_err(|e| {
            anyhow::anyhow!("Failed to restore from seed words (wrong passphrase?): {e}")
        })?
    } else {
        CipherSeed::random()
    };

    // 5. Persist
    store.set_network(network)?;
    store.set_indexer_url(&indexer_url)?;
    let enciphered = seed
        .encipher(passphrase.clone())
        .map_err(|e| anyhow::anyhow!("failed to encipher seed: {e}"))?;
    store.set_enciphered_cipher_seed(&enciphered)?;
    cli_println!(
        ANSI_GREEN,
        "✔️ Wallet initialized on {} (indexer: {})",
        network,
        indexer_url
    );

    // 6. Show the seed words for a newly created seed
    if !restore {
        let words = seed
            .to_mnemonic(MnemonicLanguage::English, passphrase.clone())
            .map_err(|e| anyhow::anyhow!("failed to encode seed words: {e}"))?;
        cli_println!();
        cli_println!(ANSI_BLUE, "Your seed words:");
        cli_println!(ANSI_WHITE, "{}", words.join(" ").reveal());
        cli_println!(
            ANSI_YELLOW,
            "⚠️ Write these down and keep them safe. They are the only way to recover your wallet."
        );
        cli_println!();
    }

    // 7. First account
    let name = match account_name {
        Some(name) => name,
        None => prompt_with_default("Name your first account", "default")?,
    };
    let index = store.next_derivation_index()?;
    let secret = keys::derive_account_secret_key(&seed, network, index);
    let account = store.insert_account(&name, index, &secret.to_address(), true)?;
    cli_println!(ANSI_GREEN, "✔️ Account '{}' created", name);
    cli_println!(ANSI_WHITE, "Address: {}", account.address);
    cli_println!(
        ANSI_WHITE,
        "Component: {}",
        account.account_component_address
    );
    cli_println!(
        ANSI_WHITE,
        "Use `show-keys` to view the account's secret keys."
    );

    // 8. Fund on testnets
    if no_fund || !network.is_testnet() {
        if !network.is_testnet() {
            cli_println!(ANSI_WHITE, "ℹ️ There is no faucet on {}.", network);
        }
        return Ok(());
    }
    let fund = if interactive {
        prompt_yes_no("Fund the account from the testnet faucet?", true)?
    } else {
        true
    };
    if fund {
        let mut provider = connect_with_wallet(common, store, network, secret).await?;
        request_faucet_funds(&mut provider, store, &account, fee_amount).await?;
    }
    Ok(())
}

fn print_account_keys(account: &AccountRecord, secret: &OotleSecretKey) {
    let account_secret_hex = Zeroizing::new(to_hex(secret.account_secret().as_bytes()));
    let view_secret_hex = Zeroizing::new(to_hex(secret.view_only_secret().as_bytes()));
    cli_println!(ANSI_BLUE, "-----------------------------------");
    cli_println!(ANSI_WHITE, "Name: {}", account.name);
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
    cli_println!(ANSI_WHITE, "Secret account key: {}", *account_secret_hex);
    cli_println!(ANSI_WHITE, "Secret view key: {}", *view_secret_hex);
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

async fn show_balances(
    common: &CommonArgs,
    store: &WalletStore,
    network: Network,
    address: &Address,
) -> anyhow::Result<()> {
    let component_address = address.to_account_address();
    let provider = connect_readonly(common, store, network).await?;

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

/// Returns the wallet's network from the database, validating any explicitly provided
/// `--network` flag against it.
fn resolve_network(common: &CommonArgs, store: &WalletStore) -> anyhow::Result<Network> {
    match (common.network, store.network()?) {
        (Some(flag), Some(db)) if flag != db => bail!(
            "--network {flag} conflicts with this wallet's network ({db}). The network is set during `setup`"
        ),
        (_, Some(db)) => Ok(db),
        (Some(flag), None) => Ok(flag),
        (None, None) => bail!("Wallet is not set up. Run `ootle setup` first"),
    }
}

/// Loads and deciphers the wallet cipher seed, prompting for the passphrase if one is
/// required and was not provided.
fn load_cipher_seed(
    common: &CommonArgs,
    store: &WalletStore,
) -> anyhow::Result<(CipherSeed, Option<SafePassword>)> {
    let enciphered = store
        .enciphered_cipher_seed()?
        .ok_or_else(|| anyhow::anyhow!("Wallet is not set up. Run `ootle setup` first"))?;
    let passphrase = common.password.clone().map(SafePassword::from);
    match CipherSeed::from_enciphered_bytes(&enciphered, passphrase.clone()) {
        Ok(seed) => Ok((seed, passphrase)),
        Err(_) if passphrase.is_none() => {
            let entered = SafePassword::from(
                prompt::prompt_password_hidden("Wallet passphrase: ")?.to_string(),
            );
            let seed = CipherSeed::from_enciphered_bytes(&enciphered, Some(entered.clone()))
                .map_err(|_| {
                    anyhow::anyhow!("Failed to decrypt the wallet seed: wrong passphrase?")
                })?;
            Ok((seed, Some(entered)))
        }
        Err(_) => bail!("Failed to decrypt the wallet seed: wrong passphrase?"),
    }
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
    store: &WalletStore,
    network: Network,
    secret: OotleSecretKey,
) -> anyhow::Result<IndexerProvider<OotleWallet>> {
    let url = resolve_indexer_url(common, store, network)?;
    let wallet = OotleWallet::new(PrivateKeyProvider::new(secret));
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_with_transaction_timeout(&url, TRANSACTION_TIMEOUT)
        .await
        .with_context(|| format!("failed to connect to indexer at {url}"))?;
    check_indexer_network(&provider, network, &url).await?;
    Ok(provider)
}

async fn connect_readonly(
    common: &CommonArgs,
    store: &WalletStore,
    network: Network,
) -> anyhow::Result<IndexerProvider<NoWallet>> {
    let url = resolve_indexer_url(common, store, network)?;
    let provider = ProviderBuilder::new()
        .with_network(network)
        .connect(&url)
        .await
        .with_context(|| format!("failed to connect to indexer at {url}"))?;
    check_indexer_network(&provider, network, &url).await?;
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
        bail!("Indexer at {url} is on network {actual}, but this wallet is on {expected}");
    }
    Ok(())
}

fn known_default_indexer_url(network: Network) -> Option<&'static str> {
    match network {
        Network::LocalNet | Network::Esmeralda => Some(ootle_rs::default_indexer_url(network)),
        _ => None,
    }
}

/// Resolution order: `--indexer-url` flag, then the wallet database setting, then the
/// known default for the network.
fn resolve_indexer_url(
    common: &CommonArgs,
    store: &WalletStore,
    network: Network,
) -> anyhow::Result<String> {
    if let Some(url) = &common.indexer_url {
        return Ok(url.to_string());
    }
    if let Some(url) = store.indexer_url()? {
        return Ok(url);
    }
    match known_default_indexer_url(network) {
        Some(url) => Ok(url.to_string()),
        None => bail!(
            "There is no default indexer URL for {network}. Set one with `set indexer-url <url>` or --indexer-url"
        ),
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
