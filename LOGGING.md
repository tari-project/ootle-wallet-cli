# Logging Configuration

This project uses `tracing` and `tracing-subscriber` for structured logging with environment-based configuration.

## Setting Log Levels

Control log output using the `RUST_LOG` environment variable:

### Windows (PowerShell)
```powershell
# Set log level to debug
$env:RUST_LOG="debug"
ootle.exe --help

# Set log level to trace (most verbose)
$env:RUST_LOG="trace"
ootle.exe scan

# Set log level for specific module
$env:RUST_LOG="ootle_wallet_cli::wallet=debug"
ootle.exe balance
```

### Windows (CMD)
```cmd
set RUST_LOG=debug
ootle.exe --help
```

### Linux/macOS
```bash
# Set log level to debug
RUST_LOG=debug ./ootle --help

# Set log level to trace
RUST_LOG=trace ./ootle scan

# Set log level for specific module
RUST_LOG=ootle_wallet_cli::wallet=debug ./ootle balance
```

## Log Levels

From least to most verbose:

- `error` - Only errors
- `warn` - Warnings and errors
- `info` - Informational messages (default)
- `debug` - Debug information
- `trace` - Most detailed logging

## Examples

```bash
# Show only warnings and errors
RUST_LOG=warn ./ootle scan

# Show all info and above
RUST_LOG=info ./ootle create-account --name test

# Show debug logs for wallet module, info for everything else
RUST_LOG=info,ootle_wallet_cli::wallet=debug ./ootle transfer

# Show all trace logs
RUST_LOG=trace ./ootle scan
```

## Advanced Filtering

You can combine multiple filters:

```bash
# Debug for wallet module, trace for specific function
RUST_LOG="ootle_wallet_cli::wallet=debug,ootle_wallet_cli::wallet::scan_for_utxos=trace" ./ootle scan

# Multiple modules
RUST_LOG="ootle_wallet_cli=debug,tari_ootle_wallet_sdk=info" ./ootle balance
```

## Default Behavior

If `RUST_LOG` is not set, the default log level is `info`.
