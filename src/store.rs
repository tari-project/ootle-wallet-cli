// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Sqlite persistence for wallet settings, accounts and transaction history. ootle-rs is
//! stateless, so the CLI keeps its own store.
//!
//! No secret keys are stored: the wallet keeps a single cipher seed (enciphered, optionally
//! with a user passphrase) in the settings table, and account keys are derived from it on
//! demand using the account's derivation index.

use std::path::Path;

use anyhow::{Context, bail};
use ootle_rs::{Address, Network, ToAccountAddress};
use rusqlite::{Connection, OptionalExtension, Row, params};
use tari_crypto::tari_utilities::hex::{from_hex, to_hex};

const SETTING_NETWORK: &str = "network";
const SETTING_CIPHER_SEED: &str = "cipher_seed";
const SETTING_INDEXER_URL: &str = "indexer_url";

pub struct WalletStore {
    conn: Connection,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AccountRecord {
    pub name: String,
    pub derivation_index: u64,
    pub address: String,
    pub account_component_address: String,
    pub account_public_key: String,
    pub view_public_key: String,
    pub is_default: bool,
}

#[derive(Debug, Clone)]
pub struct TransactionRecord {
    pub transaction_id: String,
    pub account_name: String,
    pub kind: String,
    pub status: String,
    pub details: String,
    pub created_at: String,
}

impl WalletStore {
    pub fn open<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open database {}", path.display()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS settings (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS accounts (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT NOT NULL UNIQUE,
                 derivation_index INTEGER NOT NULL UNIQUE,
                 address TEXT NOT NULL,
                 account_component_address TEXT NOT NULL,
                 account_public_key TEXT NOT NULL,
                 view_public_key TEXT NOT NULL,
                 is_default INTEGER NOT NULL DEFAULT 0,
                 created_at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             CREATE TABLE IF NOT EXISTS transactions (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 transaction_id TEXT NOT NULL,
                 account_name TEXT NOT NULL,
                 kind TEXT NOT NULL,
                 status TEXT NOT NULL,
                 details TEXT NOT NULL DEFAULT '',
                 created_at TEXT NOT NULL DEFAULT (datetime('now'))
             );",
        )
        .context("failed to run database migrations")?;
        Ok(Self { conn })
    }

    pub fn is_initialized(&self) -> anyhow::Result<bool> {
        Ok(self.get_setting(SETTING_NETWORK)?.is_some()
            && self.get_setting(SETTING_CIPHER_SEED)?.is_some())
    }

    pub fn network(&self) -> anyhow::Result<Option<Network>> {
        let value = self.get_setting(SETTING_NETWORK)?;
        value
            .map(|v| {
                v.parse::<Network>()
                    .map_err(|e| anyhow::anyhow!("invalid network in wallet database: {e:?}"))
            })
            .transpose()
    }

    pub fn set_network(&self, network: Network) -> anyhow::Result<()> {
        self.set_setting(SETTING_NETWORK, &network.to_string())
    }

    pub fn indexer_url(&self) -> anyhow::Result<Option<String>> {
        self.get_setting(SETTING_INDEXER_URL)
    }

    pub fn set_indexer_url(&self, url: &str) -> anyhow::Result<()> {
        self.set_setting(SETTING_INDEXER_URL, url)
    }

    pub fn clear_indexer_url(&self) -> anyhow::Result<()> {
        self.conn.execute(
            "DELETE FROM settings WHERE key = ?1",
            params![SETTING_INDEXER_URL],
        )?;
        Ok(())
    }

    /// Rewrites the stored account addresses for a new network. The underlying keys are
    /// network-independent; only the address encoding (and its network prefix) changes.
    pub fn update_account_addresses(&self, network: Network) -> anyhow::Result<()> {
        for account in self.list_accounts()? {
            let view_key = account.view_public_key.parse().map_err(|e| {
                anyhow::anyhow!("invalid view public key in account '{}': {e}", account.name)
            })?;
            let account_key = account.account_public_key.parse().map_err(|e| {
                anyhow::anyhow!(
                    "invalid account public key in account '{}': {e}",
                    account.name
                )
            })?;
            let address = Address::new(network, view_key, account_key);
            self.conn.execute(
                "UPDATE accounts SET address = ?1 WHERE name = ?2",
                params![address.to_string(), account.name],
            )?;
        }
        Ok(())
    }

    /// Returns the enciphered cipher seed bytes, if the wallet has been set up.
    pub fn enciphered_cipher_seed(&self) -> anyhow::Result<Option<Vec<u8>>> {
        let value = self.get_setting(SETTING_CIPHER_SEED)?;
        value
            .map(|v| from_hex(&v).context("invalid cipher seed in wallet database"))
            .transpose()
    }

    pub fn set_enciphered_cipher_seed(&self, enciphered: &[u8]) -> anyhow::Result<()> {
        self.set_setting(SETTING_CIPHER_SEED, &to_hex(enciphered))
    }

    fn get_setting(&self, key: &str) -> anyhow::Result<Option<String>> {
        let value = self
            .conn
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value)
    }

    fn set_setting(&self, key: &str, value: &str) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn insert_account(
        &mut self,
        name: &str,
        derivation_index: u64,
        address: &Address,
        set_default: bool,
    ) -> anyhow::Result<AccountRecord> {
        // The first account is always the default
        let is_default = set_default || self.count_accounts()? == 0;

        let tx = self.conn.transaction()?;
        if is_default {
            tx.execute("UPDATE accounts SET is_default = 0", [])?;
        }
        let res = tx.execute(
            "INSERT INTO accounts (name, derivation_index, address, account_component_address,
                 account_public_key, view_public_key, is_default)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                name,
                derivation_index as i64,
                address.to_string(),
                address.to_account_address().to_string(),
                address.account_public_key().to_string(),
                address.view_only_key().to_string(),
                is_default,
            ],
        );
        match res {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                bail!("An account named '{name}' already exists");
            }
            Err(e) => return Err(e).context("failed to insert account"),
        }
        tx.commit()?;

        self.get_account(Some(name))
    }

    /// Returns the next unused derivation index.
    pub fn next_derivation_index(&self) -> anyhow::Result<u64> {
        let max: Option<i64> =
            self.conn
                .query_row("SELECT MAX(derivation_index) FROM accounts", [], |row| {
                    row.get(0)
                })?;
        Ok(max.map(|m| m as u64 + 1).unwrap_or(0))
    }

    /// Returns the named account, or the default account if no name is given.
    pub fn get_account(&self, name: Option<&str>) -> anyhow::Result<AccountRecord> {
        let account = match name {
            Some(name) => self
                .conn
                .query_row(
                    "SELECT * FROM accounts WHERE name = ?1",
                    params![name],
                    row_to_account,
                )
                .optional()?,
            None => self
                .conn
                .query_row(
                    "SELECT * FROM accounts WHERE is_default = 1 LIMIT 1",
                    [],
                    row_to_account,
                )
                .optional()?,
        };
        match account {
            Some(account) => Ok(account),
            None => match name {
                Some(name) => bail!("Account '{name}' not found"),
                None => bail!("No accounts in the wallet. Run `setup` or `create-account` first"),
            },
        }
    }

    pub fn list_accounts(&self) -> anyhow::Result<Vec<AccountRecord>> {
        let mut stmt = self.conn.prepare("SELECT * FROM accounts ORDER BY id")?;
        let accounts = stmt
            .query_map([], row_to_account)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(accounts)
    }

    pub fn count_accounts(&self) -> anyhow::Result<u64> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM accounts", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    pub fn set_default_account(&self, name: &str) -> anyhow::Result<()> {
        // Validate it exists first
        self.get_account(Some(name))?;
        self.conn
            .execute("UPDATE accounts SET is_default = 0", [])?;
        self.conn.execute(
            "UPDATE accounts SET is_default = 1 WHERE name = ?1",
            params![name],
        )?;
        Ok(())
    }

    pub fn record_transaction(
        &self,
        transaction_id: &str,
        account_name: &str,
        kind: &str,
        status: &str,
        details: &str,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO transactions (transaction_id, account_name, kind, status, details)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![transaction_id, account_name, kind, status, details],
        )?;
        Ok(())
    }

    pub fn list_transactions(
        &self,
        account_name: Option<&str>,
    ) -> anyhow::Result<Vec<TransactionRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT transaction_id, account_name, kind, status, details, created_at
             FROM transactions WHERE account_name = COALESCE(?1, account_name) ORDER BY id",
        )?;
        let transactions = stmt
            .query_map(params![account_name], |row| {
                Ok(TransactionRecord {
                    transaction_id: row.get(0)?,
                    account_name: row.get(1)?,
                    kind: row.get(2)?,
                    status: row.get(3)?,
                    details: row.get(4)?,
                    created_at: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(transactions)
    }
}

fn row_to_account(row: &Row<'_>) -> rusqlite::Result<AccountRecord> {
    let derivation_index: i64 = row.get("derivation_index")?;
    Ok(AccountRecord {
        name: row.get("name")?,
        derivation_index: derivation_index as u64,
        address: row.get("address")?,
        account_component_address: row.get("account_component_address")?,
        account_public_key: row.get("account_public_key")?,
        view_public_key: row.get("view_public_key")?,
        is_default: row.get("is_default")?,
    })
}
