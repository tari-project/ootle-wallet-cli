// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Account key derivation from the wallet cipher seed.
//!
//! Uses the same derivation as the official Ootle wallet SDK (same branch strings and
//! hashing), so seed words created here can be restored in the official wallet and vice
//! versa.

use ootle_rs::Network;
use ootle_rs::crypto::derive_ristretto_key;
use ootle_rs::keys::OotleSecretKey;
use tari_common_types::seeds::cipher_seed::CipherSeed;

// Branch strings from the wallet SDK's KeyBranch::{Account, ViewOnlyKey}
const ACCOUNT_BRANCH: &str = "account";
const VIEW_ONLY_KEY_BRANCH: &str = "view_only_key";

/// Derives the account and view-only secret keys for the account at `index`.
pub fn derive_account_secret_key(
    seed: &CipherSeed,
    network: Network,
    index: u64,
) -> OotleSecretKey {
    let account_secret = derive_ristretto_key(seed.entropy(), ACCOUNT_BRANCH.as_bytes(), index);
    let view_only_secret =
        derive_ristretto_key(seed.entropy(), VIEW_ONLY_KEY_BRANCH.as_bytes(), index);
    OotleSecretKey::new(network, account_secret, view_only_secret)
}
