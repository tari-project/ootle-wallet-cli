# ootle-wallet-cli

A command-line wallet for the [Tari Ootle](https://www.tari.com/) network, built on
[ootle-rs](https://github.com/tari-project/tari-ootle/tree/development/crates/wallet/ootle-rs).

The wallet keeps its state in a local sqlite database (`data/wallet.sqlite` by default):
settings (network, indexer URL), accounts and transaction history. No secret keys are
stored - the wallet holds a single cipher seed, enciphered with an optional passphrase
(Argon2-based KDF), and account keys are derived from it on demand. Key derivation matches
the official Ootle wallet, so seed words are interchangeable between the two.

## Installation

Make sure you have Rust and Cargo installed. Then build the project:

```bash
cargo build --release
```

## Usage

```bash
# Show help
ootle-wallet --help
```

Common options (apply to all commands):

| Option | Env | Default | Description |
| --- | --- | --- | --- |
| `-d, --database-file` | `OOTLE_DB_PATH` | `data/wallet.sqlite` | Path to the wallet database |
| `-n, --network` | `OOTLE_NETWORK` | - | Network, used during `setup` (stored in the database) |
| `-i, --indexer-url` | `OOTLE_INDEXER_URL` | per-network default | Override the indexer API URL |
| `-p, --password` | `OOTLE_PASSWORD` | - | Wallet passphrase (prompted when required) |

### Initial setup

Runs you through the initial wallet setup: network, indexer URL, an optional passphrase,
new (or restored) seed words, the first account, and faucet funding on testnets:

```bash
ootle-wallet setup

# Non-interactive
ootle-wallet -n esmeralda setup --account-name main --no-fund

# Restore a wallet from existing seed words
ootle-wallet setup --restore
```

The network and indexer URL are stored in the wallet database. Default indexer URLs:
`https://ootle-indexer-a.tari.com/` (esmeralda) and `http://localhost:12500` (localnet).

### Settings

```bash
# Change the indexer API URL (empty value resets to the network default)
ootle-wallet set indexer-url https://my-indexer.example.com/
ootle-wallet set indexer-url ""

# Change the network (account addresses are re-encoded for the new network)
ootle-wallet set network localnet
```

### Accounts and keys

```bash
# Create another account (funds it from the faucet on testnets and prints its keys)
ootle-wallet create-account --name alice

# List accounts in the wallet
ootle-wallet list-accounts

# Show the keys of an account, including the secret account and view keys
ootle-wallet show-keys -a alice

# Show the wallet seed words
ootle-wallet show-seed-words

# Change the default account
ootle-wallet set-default-account -n alice
```

### Get testnet funds

```bash
# Fund the default account from the testnet faucet
ootle-wallet faucet

# Fund a specific account
ootle-wallet faucet -a alice
```

### Check balances, vaults and resources

```bash
# Default account
ootle-wallet balance

# A specific account, or any address
ootle-wallet balance -a alice
ootle-wallet balance --address otl_esm_1...

# List the on-chain vaults of an account (vault ID, resource, balances)
ootle-wallet vaults
ootle-wallet vaults -a alice

# List the resources held by an account, aggregated across its vaults
ootle-wallet resources
ootle-wallet resources --address otl_esm_1...
```

### Transfer

Public transfer of XTR to another address (amounts are in micro XTR):

```bash
ootle-wallet transfer -t otl_esm_1... -a 1000000

# From a specific account with a custom max fee
ootle-wallet transfer -s alice -t otl_esm_1... -a 1000000 -f 2000
```

### Transaction history

```bash
ootle-wallet history
ootle-wallet history -a alice
```

## Development

```bash
cargo build
cargo run -- --help
```

The Ootle crates (`ootle-rs`, `tari_template_lib_types`, `tari_ootle_common_types`) are
pulled from crates.io in `Cargo.toml`. To develop against a local checkout, comment out the
crates.io dependencies and uncomment the `path` dependencies pointing at `../dan`.
