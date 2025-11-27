# Logging Configuration

This project uses `tracing` and `tracing-subscriber` for structured logging with environment-based configuration.

## Logging to a File

To redirect logs to a file instead of console, use the `RUST_LOG_FILE` environment variable:

### Windows (PowerShell)
```powershell
# Log to file with debug level
$env:RUST_LOG="debug"
$env:RUST_LOG_FILE="ootle.log"
ootle.exe scan

# View the log file
Get-Content ootle.log -Tail 50
```

### Windows (CMD)
```cmd
set RUST_LOG=debug
set RUST_LOG_FILE=ootle.log
ootle.exe scan
```

### Linux/macOS
```bash
# Log to file
RUST_LOG=debug RUST_LOG_FILE=ootle.log ./ootle scan

# View the log file
tail -f ootle.log
```

**Note:** When `RUST_LOG_FILE` is set, logs are appended to the file (not overwritten) and ANSI color codes are disabled for cleaner file output.

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

## Complete Examples

### Debugging with file logging

```powershell
# Windows PowerShell - Debug level to file
$env:RUST_LOG="debug"
$env:RUST_LOG_FILE="data/ootle.log"
ootle.exe scan --account-name myaccount

# View logs in real-time (requires tail utility or Get-Content)
Get-Content data/ootle.log -Wait -Tail 20
```

```bash
# Linux/macOS - Trace level to file
RUST_LOG=trace RUST_LOG_FILE=data/ootle.log ./ootle scan --account-name myaccount

# View logs in real-time
tail -f data/ootle.log
```

### Module-specific logging to file

```powershell
# Log only wallet operations at trace level, everything else at info
$env:RUST_LOG="info,ootle_wallet_cli::wallet=trace"
$env:RUST_LOG_FILE="data/wallet-debug.log"
ootle.exe transfer send --to <address> --amount 1000
```

### Console vs File

```bash
# Console output (default) - includes colors
RUST_LOG=info ./ootle balance

# File output - no colors, appends to file
RUST_LOG=info RUST_LOG_FILE=ootle.log ./ootle balance
```

## Automatic Error Capturing

This application uses `tracing-error` and `color-eyre` for enhanced error reporting:

### Features

- **Span context**: When errors occur, you'll see which functions were active when the error happened
- **Better backtraces**: Errors include colorized, formatted backtraces with relevant context
- **Automatic instrumentation**: Key functions are instrumented with `#[instrument]` to capture context

### Viewing Error Context

When an error occurs, you'll see:
- The error message
- The chain of function calls that led to the error
- Relevant parameters (when logged)
- Source code locations

### Example Error Output

```
Error:   0: Failed to connect to indexer
  1: Connection timeout

Location:
   src/wallet.rs:210

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ SPANTRACE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

   0: ootle_wallet_cli::wallet::check_indexer_connection
      at src/wallet.rs:203
```

### Environment Variables for Error Reporting

```bash
# Enable backtraces (shows full stack traces on errors)
RUST_BACKTRACE=1 ./ootle scan

# Full backtrace with all frames
RUST_BACKTRACE=full ./ootle scan

# Combine with logging
RUST_LOG=debug RUST_BACKTRACE=1 ./ootle scan
```

## Tips

- Log files are appended to, not overwritten - you may want to rotate or clear them periodically
- Use trace level sparingly as it can generate very large log files
- The log file path can be relative or absolute
- Create the parent directory if it doesn't exist (e.g., `data/` in `data/ootle.log`)
- Enable `RUST_BACKTRACE=1` when debugging errors to see full stack traces
- The `#[instrument]` attribute on functions automatically captures entry/exit and errors
