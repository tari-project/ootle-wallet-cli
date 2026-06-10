# ootle-wallet-cli

A command-line wallet for the [Tari Ootle](https://www.tari.com/) network, built on
[ootle-rs](https://github.com/tari-project/tari-ootle/tree/development/crates/wallet/ootle-rs).

Account keys and transaction history are persisted in a local sqlite database
(`data/wallet.sqlite` by default). Secret keys are stored unencrypted - protect the
database file accordingly.

## Installation

Make sure you have Rust and Cargo installed. Then build the project:

```bash
cargo build --release
```

## Usage

```bash
# Show help
ootle --help
```

Common options (apply to all commands):

| Option | Env | Default | Description |
| --- | --- | --- | --- |
| `-d, --database-file` | `OOTLE_DB_PATH` | `data/wallet.sqlite` | Path to the wallet database |
| `-n, --network` | `OOTLE_NETWORK` | `esmeralda` | Network (mainnet, esmeralda, localnet, ...) |
| `-i, --indexer-url` | `OOTLE_INDEXER_URL` | per-network default | URL of an Ootle indexer API |

### Create an account

Creates a new account, funds it from the testnet faucet (skipped on mainnet or with
`--no-fund`) and outputs the account keys, including the secret account and view keys:

```bash
ootle create-account --name alice

# Also export the keys to a JSON file
ootle create-account --name alice -o alice.json
```

### Accounts and keys

```bash
# List accounts in the wallet
ootle list-accounts

# Show the keys of an account (including secret keys)
ootle show-keys -a alice

# Change the default account
ootle set-default-account -n alice
```

### Get testnet funds

```bash
# Fund the default account from the testnet faucet
ootle faucet

# Fund a specific account
ootle faucet -a alice
```

### Check balances

```bash
# Default account
ootle balance

# A specific account, or any address
ootle balance -a alice
ootle balance --address otl_esm_1...
```

### Transfer

Public transfer of XTR to another address (amounts are in micro XTR):

```bash
ootle transfer -t otl_esm_1... -a 1000000

# From a specific account with a custom max fee
ootle transfer -s alice -t otl_esm_1... -a 1000000 -f 2000
```

### Transaction history

```bash
ootle history
ootle history -a alice
```

## Development

```bash
cargo build
cargo run -- --help
```

The Ootle crates are pinned to a `tari-ootle` release tag in `Cargo.toml`. To develop
against a local checkout, comment out the `git` dependencies and uncomment the `path`
dependencies pointing at `../dan`.
