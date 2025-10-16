// Copyright 2025 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use crate::models::BalanceEntry;
use anyhow::anyhow;
use anyhow::Context;
use std::collections::{HashMap, HashSet};
use tari_crypto::ristretto::RistrettoSecretKey;
use tari_engine_types::template_lib_models::{
    ComponentAddress, ResourceAddress, StealthTransferStatement, UtxoAddress,
};
use tari_engine_types::{FromByteType, ToByteType};
use tari_ootle_common_types::displayable::Displayable;
use tari_ootle_common_types::{Network, SubstateRequirement};
use tari_ootle_wallet_sdk::apis::stealth_outputs::TransferStatementParams;
use tari_ootle_wallet_sdk::apis::stealth_transfer::OutputToCreate;
use tari_ootle_wallet_sdk::cipher_seed::CipherSeedRestore;
use tari_ootle_wallet_sdk::constants::XTR;
use tari_ootle_wallet_sdk::crypto::memo::Memo;
use tari_ootle_wallet_sdk::models::{
    AccountWithAddress, KeyBranch, KeyId, KeyType, StealthOutputModel, TransactionStatus,
    WalletLockId, WalletTransaction,
};
use tari_ootle_wallet_sdk::network::WalletNetworkInterface;
use tari_ootle_wallet_sdk::{OotleAddress, SeedWords, WalletSdk};
use tari_ootle_wallet_sdk_services::account_monitor::AccountScanner;
use tari_ootle_wallet_sdk_services::events::WalletEvent;
use tari_ootle_wallet_sdk_services::indexer_rest_api::IndexerRestApiNetworkInterface;
use tari_ootle_wallet_sdk_services::notify::Notify;
use tari_ootle_wallet_sdk_services::utxo_scanner::{UtxoRecovery, UtxoScanner};
use tari_ootle_wallet_storage_sqlite::SqliteWalletStore;
use tari_template_lib_types::crypto::RistrettoPublicKeyBytes;
use tari_template_lib_types::{Amount, ResourceType};
use tari_transaction::{Transaction, UnsignedTransaction};
use tokio::sync::broadcast;

pub type Sdk = WalletSdk<SqliteWalletStore, IndexerRestApiNetworkInterface>;

pub struct Wallet {
    sdk: Sdk,
    wallet_event_notifier: Notify<WalletEvent>,
    wallet_events_rx: broadcast::Receiver<WalletEvent>,
}

impl Wallet {
    pub fn new(sdk: Sdk) -> Self {
        let notify = Notify::new(100);
        Self {
            sdk,
            // Subscribe early to avoid missing events
            wallet_events_rx: notify.subscribe(),
            wallet_event_notifier: notify,
        }
    }

    pub fn network(&self) -> Network {
        self.sdk.network()
    }

    pub fn sdk(&self) -> &Sdk {
        &self.sdk
    }

    pub fn import_view_only_account(
        &self,
        name: &str,
        view_private_key: &RistrettoSecretKey,
        spend_public_key: RistrettoPublicKeyBytes,
    ) -> anyhow::Result<()> {
        let sdk = self.sdk();
        let key_id = sdk
            .key_manager_api()
            .import_key(name, view_private_key, KeyType::ViewOnly)
            .context("Failed to import view key")?;
        let account_address = sdk
            .accounts_api()
            .derive_account_address_from_public_key(&spend_public_key);
        sdk.accounts_api().add_account(
            Some(&format!("imported-{name}")),
            &account_address,
            key_id,
            spend_public_key,
            false,
            true,
        )?;
        Ok(())
    }

    pub fn get_account_or_default(&self, name: Option<&str>) -> anyhow::Result<AccountWithAddress> {
        let sdk = self.sdk();

        let account = match name {
            Some(name) => sdk.accounts_api().get_account_by_name(name)?,
            None => sdk.accounts_api().get_default()?,
        };
        Ok(account)
    }

    pub fn get_balances_for_account(
        &self,
        account_address: &ComponentAddress,
    ) -> anyhow::Result<BalanceStuff> {
        let sdk = self.sdk();
        let vaults = sdk.accounts_api().get_vaults_by_account(account_address)?;
        let stealth_outputs = sdk
            .stealth_outputs_api()
            .get_unspent_outputs_by_account(account_address)?;

        let mut balances = Vec::with_capacity(vaults.len());
        let mut vaulted_resources = HashSet::new();
        for vault in vaults {
            let (utxo_count, confidential_balance) = if vault.resource_type.is_stealth() {
                let (utxo_count, stealth_balance) = stealth_outputs
                    .iter()
                    .filter(|o| {
                        o.owner_account == *account_address
                            && o.resource_address == vault.resource_address
                    })
                    .map(|o| o.value)
                    .fold((0usize, Amount::zero()), |(cnt, acc), o| (cnt + 1, acc + o));

                if stealth_balance.is_positive() {
                    // If the vault exists, we add the confidential balance to this entry and, we don't want to add it again to the balances list for stealth utxos below.
                    vaulted_resources.insert(vault.resource_address);
                }

                (utxo_count, stealth_balance)
            } else {
                (0, vault.confidential_balance)
            };

            balances.push(BalanceEntry {
                vault_address: Some(vault.id),
                resource_address: vault.resource_address,
                balance: vault.revealed_balance,
                resource_type: vault.resource_type,
                confidential_balance,
                num_outputs: utxo_count,
                token_symbol: vault.token_symbol,
                divisibility: vault.divisibility,
            })
        }

        let stealth_outputs_map = stealth_outputs
            .iter()
            .filter(|o| !vaulted_resources.contains(&o.resource_address))
            .fold(HashMap::new(), |mut acc, o| {
                acc.entry(o.resource_address)
                    .and_modify(|(cnt, v)| {
                        *cnt += 1;
                        *v += o.value
                    })
                    .or_insert((1, o.value));
                acc
            });

        let all_resources = sdk.resources_api().get_many(stealth_outputs_map.keys())?;

        for (resource_address, (num_outputs, total_value)) in stealth_outputs_map {
            let resource = all_resources.get(&resource_address);
            balances.push(BalanceEntry {
                vault_address: None,
                resource_address,
                balance: Amount::zero(),
                resource_type: ResourceType::Stealth,
                confidential_balance: total_value,
                num_outputs,
                // It's not guaranteed by the wallet that we know the resource, so instead of erroring, we'll return
                // something
                token_symbol: resource
                    .as_ref()
                    .and_then(|r| r.token_symbol())
                    .map(|s| s.to_owned()),
                divisibility: resource.as_ref().map(|r| r.divisibility()).unwrap_or(0),
            });
        }

        Ok(BalanceStuff {
            balances,
            utxos: stealth_outputs,
        })
    }

    pub async fn check_indexer_connection(&self) -> anyhow::Result<()> {
        self.sdk()
            .get_network_interface()
            .wait_until_ready()
            .await
            .map_err(|e| anyhow!("Failed to connect to indexer: {}", e))
    }

    pub async fn refresh_account(&self, account_address: ComponentAddress) -> anyhow::Result<bool> {
        let updated = AccountScanner::new(self.wallet_event_notifier.clone(), self.sdk().clone())
            .refresh_account(account_address)
            .await
            .map_err(|e| anyhow!("Failed to refresh account: {}", e))?;
        Ok(updated)
    }

    pub async fn scan_for_utxos(&self, account: AccountWithAddress) -> anyhow::Result<()> {
        let scanner = UtxoScanner::new(self.sdk().clone(), self.wallet_event_notifier.clone());
        let resources = self
            .sdk()
            .accounts_api()
            .get_associated_stealth_resources(account.component_address())?;
        let mut num_found_total = 0;
        for resource_addr in resources {
            // Ensure that the resource is in the local database
            let resource = self
                .sdk
                .substate_api()
                .fetch_resource(resource_addr)
                .await?;
            self.sdk
                .resources_api()
                .upsert_resource(&resource_addr, &resource)?;

            let stats = scanner
                .scan_and_enqueue_utxos(&account, &resource_addr)
                .await?;
            if stats.num_potential_recoveries > 0 {
                log::info!(
                    "Found {} potential stealth UTXOs for account {} resource {}",
                    stats.num_potential_recoveries,
                    account,
                    resource_addr
                );
            }
            num_found_total += stats.num_potential_recoveries;
        }

        if num_found_total > 0 {
            UtxoRecovery::new(self.sdk().clone())
                .with_notify(self.wallet_event_notifier.clone())
                .process_utxo_validation_queue()
                .await?;
        }
        Ok(())
    }

    pub fn drain_events(&mut self) -> Vec<WalletEvent> {
        let mut events = vec![];
        while let Ok(event) = self.wallet_events_rx.try_recv() {
            events.push(event);
        }
        events
    }

    pub fn create_seed_words(&mut self) -> anyhow::Result<SeedWords> {
        self.sdk
            .initialize_cipher_seed(CipherSeedRestore::CreateNewIfRequired)?;
        let seed_words = self
            .sdk
            .load_seed_words()?
            .expect("Bug: seed words were initialized however load_seed_words returned None");
        Ok(seed_words)
    }

    pub fn create_account(
        &mut self,
        name: &str,
        set_default: bool,
    ) -> anyhow::Result<AccountWithAddress> {
        self.sdk
            .initialize_cipher_seed(CipherSeedRestore::CreateNewIfRequired)?;
        let address = self.sdk.key_manager_api().next_account_address()?;
        let account = self
            .sdk
            .accounts_api()
            .create_account(Some(name), set_default, address)?;
        Ok(account)
    }

    pub fn create_transfer(
        &self,
        src_account: Option<&str>,
        dest_address: &OotleAddress,
        fee_amount: u64,
        amount: u64,
        outputs: &[u64],
        message: Option<&str>,
    ) -> anyhow::Result<TransferOutput> {
        assert_eq!(
            outputs.iter().sum::<u64>(),
            amount,
            "Outputs do not sum to input amount"
        );
        let src_account = match src_account {
            Some(name) => self.sdk().accounts_api().get_account_by_name(name).unwrap(),
            None => self.sdk().accounts_api().get_default().unwrap(),
        };
        let spend_key_id = src_account.owner_key_id().ok_or_else(|| {
            anyhow::anyhow!("Source account does not have the required spend key")
        })?;
        let view_key_id = src_account.view_only_key_id();

        let outputs_api = self.sdk().stealth_outputs_api();

        let lock_id = outputs_api.create_lock()?;
        let (inputs, total_locked_amount) = outputs_api.lock_outputs_for_at_least_amount(
            src_account.component_address(),
            &XTR,
            lock_id,
            amount + fee_amount,
        )?;

        let dest_address = dest_address.try_from_byte_type().map_err(|err| {
            anyhow!("Destination address is not a Ristretto Ootle address: {err}")
        })?;

        let inputs = inputs
            .into_iter()
            .map(|o| o.into_spend_data())
            .collect::<Vec<_>>();
        let memo = message
            .map(|s| {
                Memo::new_message(s).ok_or_else(|| {
                    anyhow::anyhow!("Failed to create memo from message. Message too long?")
                })
            })
            .transpose()?;
        let src_address = src_account.address.try_from_byte_type()?;

        let ch_memo = Memo::new_message("Change").unwrap();
        let change_output = Some(OutputToCreate {
            owner_address: &src_address,
            amount: total_locked_amount - Amount::from(amount) - Amount::from(fee_amount),
            memo: Some(&ch_memo),
        })
        .filter(|o| o.amount.is_positive());

        let memos = outputs
            .iter()
            .enumerate()
            .map(|(i, _)| {
                memo.as_ref()
                    .map(|m| format!("{}: {}/{}", m.as_message().unwrap(), i + 1, outputs.len()))
                    .map(|m| Memo::new_message(m).unwrap())
            })
            .collect::<Vec<_>>();

        let transfer_outputs = outputs
            .iter()
            .zip(&memos)
            .map(|(&amt, memo)| OutputToCreate {
                owner_address: &dest_address,
                amount: amt.into(),
                memo: memo.as_ref(),
            });

        let nonce_key = self
            .sdk
            .key_manager_api()
            .next_public_key(KeyBranch::Nonce)?;

        let params = TransferStatementParams {
            spend_key_branch: KeyBranch::Account,
            spend_key_id,
            view_only_key_id: view_key_id,
            resource_address: &XTR,
            resource_view_key: None,
            inputs: &inputs,
            input_revealed_amount: Amount::zero(),
            outputs: transfer_outputs.chain(change_output),
            // TODO: this only works with XTR
            output_revealed_amount: fee_amount.into(),
            required_signer: nonce_key.public_key.to_byte_type(),
        };

        let transfer = outputs_api.generate_transfer_statement(params)?;

        Ok(TransferOutput {
            statement: transfer,
            resource_address: XTR,
            lock_id,
            required_signer_key_branch: KeyBranch::Nonce,
            required_signer_key_id: nonce_key.key_id,
        })
    }

    pub fn sign_transaction(
        &self,
        transaction: UnsignedTransaction,
        key_branch: KeyBranch,
        key_id: KeyId,
    ) -> Transaction {
        self.sdk
            .local_signer_api()
            .sign(
                key_branch,
                key_id,
                transaction.authorized_sealed_signer().build(),
            )
            .unwrap()
    }

    pub fn create_transfer_transaction(&self, transfer: &TransferOutput) -> UnsignedTransaction {
        let inputs = transfer
            .statement
            .inputs_statement
            .inputs
            .iter()
            .map(|i| UtxoAddress::new(transfer.resource_address, i.commitment.into()))
            .map(SubstateRequirement::unversioned);

        Transaction::builder()
            .for_network(self.network().as_byte())
            .with_fee_instructions_builder(|builder| {
                builder.pay_fee_stealth(transfer.statement.clone())
            })
            .with_inputs(inputs)
            .add_input(XTR)
            .build_unsigned_transaction()
    }

    pub async fn submit_transaction(
        &self,
        lock_id: WalletLockId,
        transaction: Transaction,
    ) -> anyhow::Result<WalletTransaction> {
        let id = self
            .sdk
            .transaction_api()
            .insert_new_transaction(transaction, None, false)?;
        self.sdk
            .stealth_outputs_api()
            .locks_set_transaction_id(lock_id, id)?;
        if !self.sdk.transaction_api().submit_transaction(id).await? {
            return Err(anyhow!("Failed to submit transaction {}", id));
        }

        loop {
            let maybe_tx = self
                .sdk()
                .transaction_api()
                .check_and_store_finalized_transaction(id)
                .await?;
            match maybe_tx {
                Some(tx) => {
                    if matches!(tx.status, TransactionStatus::Accepted) {
                        log::info!("Transaction {} was accepted", id);
                        return Ok(tx);
                    } else {
                        return Err(anyhow!(
                            "Transaction {} failed: {:?} {} {}",
                            id,
                            tx.status,
                            tx.invalid_reason.as_deref().unwrap_or(""),
                            tx.finalize
                                .as_ref()
                                .and_then(|f| f.result.any_reject())
                                .display()
                        ));
                    }
                }
                None => {
                    log::info!("Transaction {} is still pending...", id);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TransferOutput {
    pub statement: StealthTransferStatement,
    pub lock_id: WalletLockId,
    pub resource_address: ResourceAddress,
    pub required_signer_key_branch: KeyBranch,
    pub required_signer_key_id: KeyId,
}

pub struct BalanceStuff {
    pub balances: Vec<BalanceEntry>,
    pub utxos: Vec<StealthOutputModel>,
}
