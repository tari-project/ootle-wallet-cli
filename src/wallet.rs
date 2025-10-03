// Copyright 2025 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use crate::models::BalanceEntry;
use anyhow::anyhow;
use anyhow::Context;
use blake2::digest::Update;
use blake2::Digest;
use futures::future;
use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use tari_crypto::ristretto::RistrettoSecretKey;
use tari_crypto::tari_utilities::SafePassword;
use tari_engine_types::template_lib_models::ComponentAddress;
use tari_ootle_common_types::Network;
use tari_ootle_wallet_sdk::models::KeyType;
use tari_ootle_wallet_sdk::WalletSdk;
use tari_ootle_wallet_sdk_services::account_monitor::{AccountMonitor, AccountMonitorHandle};
use tari_ootle_wallet_sdk_services::indexer_jrpc::IndexerJsonRpcNetworkInterface;
use tari_ootle_wallet_sdk_services::notify::Notify;
use tari_ootle_wallet_sdk_services::transaction_service::{
    TransactionService, TransactionServiceHandle,
};
use tari_ootle_wallet_sdk_services::utxo_scanner::{
    StealthUtxoScannerWorker, UtxoRecovery, UtxoScannerHandle,
};
use tari_ootle_wallet_sdk_services::Shutdown;
use tari_ootle_wallet_storage_sqlite::SqliteWalletStore;
use tari_template_lib_types::crypto::RistrettoPublicKeyBytes;
use tari_template_lib_types::{Amount, ResourceType};
use tokio::task::JoinHandle;

pub type Sdk = WalletSdk<SqliteWalletStore, IndexerJsonRpcNetworkInterface>;

pub struct Wallet {
    sdk: Sdk,
}

impl Wallet {
    pub fn new(sdk: Sdk) -> Self {
        Self { sdk }
    }

    pub fn into_spawned(self) -> SpawnedWallet {
        SpawnedWallet {
            inner: spawn_services(self),
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
            None,
            &account_address,
            key_id,
            spend_public_key,
            false,
            true,
        )?;
        Ok(())
    }

    pub fn get_balances_for_account(
        &self,
        account_address: &ComponentAddress,
    ) -> anyhow::Result<Vec<BalanceEntry>> {
        let sdk = self.sdk();
        let vaults = sdk.accounts_api().get_vaults_by_account(account_address)?;
        let stealth_outputs = sdk
            .stealth_outputs_api()
            .get_unspent_outputs_by_account(account_address)?;

        let mut balances = Vec::with_capacity(vaults.len());
        let mut vaulted_resources = HashSet::new();
        for vault in vaults {
            let confidential_balance = if vault.resource_type.is_stealth() {
                let stealth_balance = stealth_outputs
                    .iter()
                    .filter(|o| {
                        o.owner_account == *account_address
                            && o.resource_address == vault.resource_address
                    })
                    .map(|o| o.value)
                    .sum::<Amount>();

                if stealth_balance.is_positive() {
                    // If the vault has a confidential balance, we don't want to add it to the balances list
                    // as it is already included in the vault's revealed balance.
                    vaulted_resources.insert(vault.resource_address);
                }
                stealth_balance
            } else {
                vault.confidential_balance
            };

            balances.push(BalanceEntry {
                vault_address: Some(vault.id),
                resource_address: vault.resource_address,
                balance: vault.revealed_balance,
                resource_type: vault.resource_type,
                confidential_balance,
                token_symbol: vault.token_symbol,
                divisibility: vault.divisibility,
            })
        }

        let stealth_outputs = stealth_outputs
            .into_iter()
            .filter(|o| !vaulted_resources.contains(&o.resource_address))
            .fold(HashMap::new(), |mut acc, o| {
                acc.entry(o.resource_address)
                    .and_modify(|v| *v += o.value)
                    .or_insert(o.value);
                acc
            });

        let all_resources = sdk.resources_api().get_many(stealth_outputs.keys())?;

        for (resource_address, total_value) in stealth_outputs {
            let resource = all_resources.get(&resource_address);
            balances.push(BalanceEntry {
                vault_address: None,
                resource_address,
                balance: Amount::zero(),
                resource_type: ResourceType::Stealth,
                confidential_balance: total_value,
                // It's not guaranteed by the wallet that we know the resource, so instead of erroring, we'll return
                // something
                token_symbol: resource
                    .as_ref()
                    .and_then(|r| r.token_symbol())
                    .map(|s| s.to_owned()),
                divisibility: resource.as_ref().map(|r| r.divisibility()).unwrap_or(0),
            });
        }

        Ok(balances)
    }
}

pub struct SpawnedWallet {
    inner: Services,
}

impl SpawnedWallet {
    pub fn sdk(&self) -> &Sdk {
        self.inner.wallet.sdk()
    }

    pub async fn refresh_account(&self, account_address: ComponentAddress) -> anyhow::Result<bool> {
        let updated = self
            .inner
            .account_monitor
            .refresh_account(account_address)
            .await?;
        Ok(updated)
    }
    pub fn get_balances_for_account(
        &self,
        account_address: &ComponentAddress,
    ) -> anyhow::Result<Vec<BalanceEntry>> {
        self.inner.wallet.get_balances_for_account(account_address)
    }

    pub fn shutdown(mut self) -> Wallet {
        self.inner.shutdown.trigger();
        self.inner.wallet
    }
}

fn spawn_services(wallet: Wallet) -> Services {
    let sdk = wallet.sdk();
    let notify = Notify::new(100);
    let shutdown = Shutdown::new();
    let (transaction_service, transaction_service_handle) =
        TransactionService::new(notify.clone(), sdk.clone(), shutdown.to_signal());
    let transaction_service_join_handle = tokio::spawn(transaction_service.run());

    let utxo_scanner = StealthUtxoScannerWorker::new(sdk.clone());
    let (utxo_scanner_join_handle, utxo_scanner_handle) = utxo_scanner.spawn();

    let utxo_recovery_join_handle = {
        let sdk = sdk.clone();
        let notify_sub = utxo_scanner_handle.subscribe_notifications();
        tokio::spawn(UtxoRecovery::new(sdk).run(notify_sub))
    };

    let (account_monitor, account_monitor_handle) = AccountMonitor::new(
        notify,
        sdk.clone(),
        utxo_scanner_handle.clone(),
        shutdown.to_signal(),
    );
    let account_monitor_join_handle = tokio::spawn(account_monitor.run());

    Services {
        shutdown,
        wallet,
        utxo_scanner: utxo_scanner_handle,
        account_monitor: account_monitor_handle,
        transaction_service: transaction_service_handle,
        services_fut: Box::pin(try_select_any([
            transaction_service_join_handle,
            account_monitor_join_handle,
            utxo_scanner_join_handle,
            utxo_recovery_join_handle,
        ])),
    }
}

struct Services {
    pub shutdown: Shutdown,
    pub services_fut: Pin<Box<dyn Future<Output = Result<(), anyhow::Error>>>>,
    pub utxo_scanner: UtxoScannerHandle,
    pub account_monitor: AccountMonitorHandle,
    pub transaction_service: TransactionServiceHandle,
    pub wallet: Wallet,
}

async fn try_select_any<I>(handles: I) -> Result<(), anyhow::Error>
where
    I: IntoIterator<Item = JoinHandle<Result<(), anyhow::Error>>>,
{
    let (res, _, _) = future::select_all(handles).await;
    res.unwrap_or_else(|e| Err(anyhow!("Task panicked: {}", e)))
}

fn hash_password(password: &SafePassword) -> chacha20poly1305::Key {
    blake2::Blake2b::new_with_prefix(b"password")
        .chain(password.reveal())
        .finalize()
}
