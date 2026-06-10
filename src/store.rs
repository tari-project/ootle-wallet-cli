// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Sqlite persistence for accounts and transaction history. ootle-rs is stateless, so the
//! CLI keeps its own store of account keys and submitted transactions.

use std::path::Path;

use anyhow::{Context, bail};
use ootle_rs::keys::OotleSecretKey;
use ootle_rs::{Network, ToAccountAddress};
use rusqlite::{Connection, OptionalExtension, Row, params};
use tari_crypto::ristretto::RistrettoSecretKey;
use tari_crypto::tari_utilities::ByteArray;
use tari_crypto::tari_utilities::hex::{from_hex, to_hex};
use zeroize::Zeroizing;

pub struct WalletStore {
    conn: Connection,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AccountRecord {
    pub name: String,
    pub network: String,
    pub address: String,
    pub account_component_address: String,
    pub account_public_key: String,
    pub view_public_key: String,
    pub account_secret_key: String,
    pub view_secret_key: String,
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
            "CREATE TABLE IF NOT EXISTS accounts (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT NOT NULL UNIQUE,
                 network TEXT NOT NULL,
                 address TEXT NOT NULL,
                 account_component_address TEXT NOT NULL,
                 account_public_key TEXT NOT NULL,
                 view_public_key TEXT NOT NULL,
                 account_secret_key TEXT NOT NULL,
                 view_secret_key TEXT NOT NULL,
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

    pub fn insert_account(
        &mut self,
        name: &str,
        secret: &OotleSecretKey,
        set_default: bool,
    ) -> anyhow::Result<AccountRecord> {
        let address = secret.to_address();
        // The first account is always the default
        let is_default = set_default || self.count_accounts()? == 0;

        let tx = self.conn.transaction()?;
        if is_default {
            tx.execute("UPDATE accounts SET is_default = 0", [])?;
        }
        let res = tx.execute(
            "INSERT INTO accounts (name, network, address, account_component_address,
                 account_public_key, view_public_key, account_secret_key, view_secret_key, is_default)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                name,
                secret.network().to_string(),
                address.to_string(),
                address.to_account_address().to_string(),
                address.account_public_key().to_string(),
                address.view_only_key().to_string(),
                to_hex(secret.account_secret().as_bytes()),
                to_hex(secret.view_only_secret().as_bytes()),
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
                None => bail!("No accounts in the wallet. Create one with `create-account`"),
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

impl AccountRecord {
    pub fn to_secret_key(&self) -> anyhow::Result<OotleSecretKey> {
        let network = self
            .network
            .parse::<Network>()
            .map_err(|e| anyhow::anyhow!("invalid network in account '{}': {e:?}", self.name))?;
        let account_secret = parse_secret_key(&self.account_secret_key)
            .with_context(|| format!("invalid account secret key in account '{}'", self.name))?;
        let view_secret = parse_secret_key(&self.view_secret_key)
            .with_context(|| format!("invalid view secret key in account '{}'", self.name))?;
        Ok(OotleSecretKey::new(network, account_secret, view_secret))
    }
}

fn row_to_account(row: &Row<'_>) -> rusqlite::Result<AccountRecord> {
    Ok(AccountRecord {
        name: row.get("name")?,
        network: row.get("network")?,
        address: row.get("address")?,
        account_component_address: row.get("account_component_address")?,
        account_public_key: row.get("account_public_key")?,
        view_public_key: row.get("view_public_key")?,
        account_secret_key: row.get("account_secret_key")?,
        view_secret_key: row.get("view_secret_key")?,
        is_default: row.get("is_default")?,
    })
}

fn parse_secret_key(hex: &str) -> anyhow::Result<RistrettoSecretKey> {
    let bytes = Zeroizing::new(from_hex(hex).context("not valid hex")?);
    let key = RistrettoSecretKey::from_canonical_bytes(&bytes)
        .map_err(|e| anyhow::anyhow!("not a valid Ristretto secret key: {e}"))?;
    Ok(key)
}
