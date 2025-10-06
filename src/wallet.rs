// Copyright 2025 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use crate::models::BalanceEntry;
use anyhow::anyhow;
use anyhow::Context;
use std::collections::{HashMap, HashSet};
use tari_crypto::ristretto::RistrettoSecretKey;
use tari_engine_types::template_lib_models::ComponentAddress;
use tari_ootle_common_types::Network;
use tari_ootle_wallet_sdk::models::{AccountWithAddress, KeyType};
use tari_ootle_wallet_sdk::network::WalletNetworkInterface;
use tari_ootle_wallet_sdk::WalletSdk;
use tari_ootle_wallet_sdk_services::account_monitor::AccountScanner;
use tari_ootle_wallet_sdk_services::events::WalletEvent;
use tari_ootle_wallet_sdk_services::indexer_jrpc::IndexerJsonRpcNetworkInterface;
use tari_ootle_wallet_sdk_services::notify::Notify;
use tari_ootle_wallet_sdk_services::utxo_scanner::{UtxoRecovery, UtxoScanner};
use tari_ootle_wallet_storage_sqlite::SqliteWalletStore;
use tari_template_lib_types::crypto::RistrettoPublicKeyBytes;
use tari_template_lib_types::{Amount, ResourceType};
use tokio::sync::broadcast;

pub type Sdk = WalletSdk<SqliteWalletStore, IndexerJsonRpcNetworkInterface>;

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
    ) -> anyhow::Result<Vec<BalanceEntry>> {
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
        for resource in resources {
            let stats = scanner.scan_and_enqueue_utxos(&account, &resource).await?;
            if stats.num_recovered > 0 {
                log::info!(
                    "Found {} new stealth UTXOs for account {} resource {}",
                    stats.num_recovered,
                    account,
                    resource
                );
            }
            num_found_total += stats.num_recovered;
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
}
