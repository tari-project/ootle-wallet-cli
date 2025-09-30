# ootle-wallet-cli

A command-line interface for Ootle wallet operations built with Rust and Clap.

## Installation

Make sure you have Rust and Cargo installed. Then build the project:

```bash
cargo build --release
```

## Usage

The CLI provides several commands for wallet management:

### Basic Usage

```bash
# Show help
ootle-wallet-cli --help

# Show version
ootle-wallet-cli --version
```

### Commands

#### Create a new wallet
```bash
# Create a wallet without password
ootle-wallet-cli create --name my-wallet

# Create a wallet with password protection
ootle-wallet-cli create --name secure-wallet --password mypassword
```

#### List all wallets
```bash
ootle-wallet-cli list
```

#### Check wallet balance
```bash
ootle-wallet-cli balance --name my-wallet
```

#### Send funds
```bash
ootle-wallet-cli send --from my-wallet --to recipient-address --amount 100.0
```

### Command Help

You can get help for any specific command:

```bash
ootle-wallet-cli create --help
ootle-wallet-cli send --help
```

## Development

### Build
```bash
cargo build
```

### Run
```bash
cargo run -- --help
# or
./target/debug/ootle-wallet-cli --help
```

### Test
```bash
cargo test
```

## Features

- Create wallets with optional password protection
- List available wallets
- Check wallet balances
- Send transactions between wallets
- Comprehensive help system
- Built with modern Rust and Clap CLI framework