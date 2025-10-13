// Transfer sub command
use crate::wallet::Wallet;
use crate::{cli_println, write_to_json_file, ANSI_GREEN, ANSI_WHITE};
use anyhow::Context;
use clap::Subcommand;
use std::path::Path;
use tari_ootle_wallet_sdk::models::WalletLockId;
use tari_ootle_wallet_sdk::OotleAddress;
use tari_transaction::{Transaction, UnsignedTransaction};

#[derive(Subcommand)]
pub enum TransferCommand {
    Create {
        #[arg(short = 's', long, help = "The source account name")]
        from_account: Option<Box<str>>,
        #[arg(short = 't', long, help = "The destination address")]
        to_address: OotleAddress,
        #[arg(short, long, help = "The amount to transfer")]
        amount: u64,
        #[arg(
            short = 'f',
            long,
            default_value_t = 1000,
            help = "Fee amount to include in the transfer (WARN: fees will be used in full without refunds)"
        )]
        fee_amount: u64,
        #[arg(
            short = 'm',
            long,
            help = "Optional message to include in the transfer"
        )]
        message: Option<Box<str>>,
        #[arg(
            short = 'o',
            long,
            help = "Output file to save the transfer details as JSON"
        )]
        output_file: Option<Box<Path>>,
    },
    #[clap(alias = "transaction")]
    CreateTransaction {
        /// Path to a JSON file containing the transfer statement.
        transfer_file: Box<Path>,
        /// Output file to save the unsigned transfer transaction as JSON.
        output_file: Box<Path>,
    },
    Sign {
        /// Path to a JSON file containing the unsigned transfer transaction.
        transaction_file: Box<Path>,
        /// Output file to save the signed transfer transaction as JSON.
        output_file: Box<Path>,
    },
    #[clap(alias = "send")]
    Submit {
        /// Path to a JSON file containing the signed transfer transaction.
        transaction_file: Box<Path>,
    },
    /// Releases a previously acquired transfer lock allowing the locked funds to be spent again.
    #[clap(alias = "unlock")]
    ReleaseLock { lock_id: WalletLockId },
}

pub async fn handle_transfer_command(
    wallet: &mut Wallet,
    command: TransferCommand,
) -> Result<(), anyhow::Error> {
    match command {
        TransferCommand::Create {
            from_account,
            to_address,
            fee_amount,
            amount,
            message,
            output_file,
        } => {
            let transfer = wallet.create_transfer(
                from_account.as_deref(),
                &to_address,
                fee_amount,
                amount,
                message.as_deref(),
            )?;

            cli_println!(ANSI_GREEN, "✔️ Transfer created successfully");
            let json = serde_json::to_value(&transfer)?;
            cli_println!(ANSI_WHITE, "{:#}", json);
            if let Some(path) = output_file {
                write_to_json_file(&json, &path).context("failed to write transfer to file")?;
                cli_println!(
                    ANSI_WHITE,
                    "Transfer written to {} successfully",
                    path.display()
                );
            }
        }
        TransferCommand::CreateTransaction {
            transfer_file,
            output_file,
        } => {
            let transfer = serde_json::from_reader(
                std::fs::File::open(transfer_file).context("failed to open transfer file")?,
            )
            .context("failed to parse transfer file")?;
            let transaction = wallet.create_transfer_transaction(&transfer);
            cli_println!(ANSI_GREEN, "✔️ Transfer transaction created successfully");
            write_to_json_file(
                &UnsignedTransactionOutput {
                    transaction,
                    lock_id: transfer.lock_id,
                },
                &output_file,
            )?;
            cli_println!(
                ANSI_WHITE,
                "Unsigned transaction written to {} successfully",
                output_file.display()
            );
        }
        TransferCommand::Sign {
            transaction_file,
            output_file,
        } => {
            let data: UnsignedTransactionOutput = serde_json::from_reader(
                std::fs::File::open(&transaction_file)
                    .context("failed to open transaction file")?,
            )
            .context("failed to parse transaction file")?;
            let signed_transaction = wallet.sign_transaction(data.transaction);
            cli_println!(ANSI_GREEN, "✔️ Transfer transaction signed successfully");
            write_to_json_file(
                &SignedTransactionOutput {
                    transaction: signed_transaction,
                    lock_id: data.lock_id,
                },
                &output_file,
            )?;
            cli_println!(
                ANSI_WHITE,
                "Signed transaction written to {} successfully",
                output_file.display()
            );
        }
        TransferCommand::Submit { transaction_file } => {
            let data: SignedTransactionOutput = serde_json::from_reader(
                std::fs::File::open(&transaction_file)
                    .context("failed to open transaction file")?,
            )
            .context("failed to parse transaction file")?;
            let tx_id = data.transaction.calculate_id();
            let tx = wallet
                .submit_transaction(data.lock_id, data.transaction)
                .await?;

            cli_println!(ANSI_GREEN, "✔️ Transfer transaction submitted successfully");
            cli_println!(ANSI_WHITE, "Transaction ID: {} {:?}", tx_id, tx.status);
            cli_println!(
                ANSI_WHITE,
                "Exec time: {:?} Finalize time: {:?}",
                tx.execution_time,
                tx.finalized_time
            );
        }
        TransferCommand::ReleaseLock { lock_id } => {
            wallet.sdk().stealth_outputs_api().release_lock(lock_id)?;
            cli_println!(ANSI_GREEN, "✔️ Transfer lock released successfully");
        }
    }

    Ok(())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UnsignedTransactionOutput {
    pub transaction: UnsignedTransaction,
    pub lock_id: WalletLockId,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedTransactionOutput {
    pub transaction: Transaction,
    pub lock_id: WalletLockId,
}
