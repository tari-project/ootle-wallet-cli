// Copyright 2025 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use crate::models::BalanceEntry;
use anyhow::anyhow;
use anyhow::Context;
use futures::future;
use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use tari_crypto::ristretto::RistrettoSecretKey;
use tari_engine_types::template_lib_models::ComponentAddress;
use tari_ootle_common_types::Network;
use tari_ootle_wallet_sdk::models::{AccountWithAddress, KeyType};
use tari_ootle_wallet_sdk::network::WalletNetworkInterface;
use tari_ootle_wallet_sdk::WalletSdk;
use tari_ootle_wallet_sdk_services::account_monitor::{AccountMonitor, AccountMonitorHandle};
use tari_ootle_wallet_sdk_services::indexer_jrpc::IndexerJsonRpcNetworkInterface;
use tari_ootle_wallet_sdk_services::notify::Notify;
use tari_ootle_wallet_sdk_services::utxo_scanner::{
    StealthUtxoScannerWorker, UtxoRecovery, UtxoRecoveryEvent, UtxoScanner, UtxoScannerHandle,
};
use tari_ootle_wallet_sdk_services::Shutdown;
use tari_ootle_wallet_storage_sqlite::SqliteWalletStore;
use tari_template_lib_types::crypto::RistrettoPublicKeyBytes;
use tari_template_lib_types::{Amount, ResourceType};
use tokio::sync::{broadcast, watch};
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
            services: spawn_services(self),
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
                num_outputs: 0,
                token_symbol: vault.token_symbol,
                divisibility: vault.divisibility,
            })
        }

        let stealth_outputs = stealth_outputs
            .into_iter()
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

        let all_resources = sdk.resources_api().get_many(stealth_outputs.keys())?;

        for (resource_address, (num_outputs, total_value)) in stealth_outputs {
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

        Ok(balances)
    }

    pub async fn check_indexer_connection(&self) -> anyhow::Result<()> {
        self.sdk()
            .get_network_interface()
            .wait_until_ready()
            .await
            .map_err(|e| anyhow!("Failed to connect to indexer: {}", e))
    }
}

pub struct SpawnedWallet {
    services: Services,
}

impl SpawnedWallet {
    pub fn sdk(&self) -> &Sdk {
        self.services.wallet.sdk()
    }

    pub async fn check_indexer_connection(&self) -> anyhow::Result<()> {
        self.services.wallet.check_indexer_connection().await
    }

    pub fn get_account_or_default(&self, name: Option<&str>) -> anyhow::Result<AccountWithAddress> {
        self.services.wallet.get_account_or_default(name)
    }

    pub async fn refresh_account(&self, account_address: ComponentAddress) -> anyhow::Result<bool> {
        let updated = self
            .services
            .account_monitor
            .refresh_account(account_address)
            .await?;
        Ok(updated)
    }

    pub async fn scan_for_utxos(&self, account: AccountWithAddress) -> anyhow::Result<()> {
        let scanner = UtxoScanner::new(self.sdk().clone());
        let resources = self
            .sdk()
            .accounts_api()
            .get_associated_stealth_resources(account.component_address())?;
        let (notify_tx, mut notify_rx) = watch::channel(());
        notify_rx.mark_unchanged();
        for resource in resources {
            let num_found = scanner
                .scan_and_enqueue_utxos(&account, &resource, &notify_tx)
                .await?;
            if num_found > 0 {
                log::info!(
                    "Found {} new stealth UTXOs for account {} resource {}",
                    num_found,
                    account,
                    resource
                );
            }
        }
        if notify_rx.has_changed()? {
            UtxoRecovery::new(self.sdk().clone())
                .process_utxo_validation_queue()
                .await?;
        }
        Ok(())
    }

    pub fn drain_events(&mut self) -> Vec<UtxoRecoveryEvent> {
        let mut events = vec![];
        while let Ok(event) = self.services.recovery_events.try_recv() {
            events.push(event);
        }
        events
    }

    pub fn shutdown(mut self) -> Wallet {
        self.services._shutdown.trigger();
        self.services.wallet
    }
}

fn spawn_services(wallet: Wallet) -> Services {
    let sdk = wallet.sdk();
    let notify = Notify::new(100);
    let shutdown = Shutdown::new();

    let utxo_scanner = StealthUtxoScannerWorker::new(sdk.clone());
    let (utxo_scanner_join_handle, utxo_scanner_handle) = utxo_scanner.spawn();

    let notify_sub = utxo_scanner_handle.subscribe_notifications();
    let (tx, recovery_events) = broadcast::channel(100);
    let utxo_recovery_join_handle = tokio::spawn(
        UtxoRecovery::new(sdk.clone())
            .with_events(tx)
            .run(notify_sub),
    );

    let (account_monitor, account_monitor_handle) = AccountMonitor::new(
        notify,
        sdk.clone(),
        utxo_scanner_handle.clone(),
        shutdown.to_signal(),
    );
    let account_monitor_join_handle =
        tokio::spawn(account_monitor.disable_periodic_scanning_with_utxos().run());

    Services {
        _shutdown: shutdown,
        wallet,
        recovery_events,
        _utxo_scanner: utxo_scanner_handle,
        account_monitor: account_monitor_handle,
        _services_fut: Box::pin(try_select_any([
            account_monitor_join_handle,
            utxo_scanner_join_handle,
            utxo_recovery_join_handle,
        ])),
    }
}

struct Services {
    pub _shutdown: Shutdown,
    pub recovery_events: broadcast::Receiver<UtxoRecoveryEvent>,
    pub _services_fut: Pin<Box<dyn Future<Output = Result<(), anyhow::Error>>>>,
    pub _utxo_scanner: UtxoScannerHandle,
    pub account_monitor: AccountMonitorHandle,
    pub wallet: Wallet,
}

async fn try_select_any<I>(handles: I) -> Result<(), anyhow::Error>
where
    I: IntoIterator<Item = JoinHandle<Result<(), anyhow::Error>>>,
{
    let (res, _, _) = future::select_all(handles).await;
    res.unwrap_or_else(|e| Err(anyhow!("Task panicked: {}", e)))
}
