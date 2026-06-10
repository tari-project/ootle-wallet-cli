// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Small helpers for interactive prompts during `setup`.

use std::io::Write;

use anyhow::Context;
use zeroize::Zeroizing;

pub fn prompt_line(message: &str) -> anyhow::Result<String> {
    print!("{message}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("failed to read input")?;
    Ok(line.trim().to_string())
}

pub fn prompt_with_default(message: &str, default: &str) -> anyhow::Result<String> {
    let input = prompt_line(&format!("{message} [{default}]: "))?;
    if input.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(input)
    }
}

pub fn prompt_yes_no(message: &str, default: bool) -> anyhow::Result<bool> {
    let hint = if default { "Y/n" } else { "y/N" };
    let input = prompt_line(&format!("{message} [{hint}]: "))?;
    match input.to_lowercase().as_str() {
        "" => Ok(default),
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        other => {
            cli_println!(White, "Please answer 'y' or 'n', got '{}'", other);
            prompt_yes_no(message, default)
        }
    }
}

/// Prompts for a passphrase with hidden input when attached to a terminal, falling back to
/// reading a line from stdin when input is piped.
pub fn prompt_password_hidden(message: &str) -> anyhow::Result<Zeroizing<String>> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        Ok(Zeroizing::new(
            rpassword::prompt_password(message).context("failed to read passphrase")?,
        ))
    } else {
        Ok(Zeroizing::new(prompt_line(message)?))
    }
}

/// Prompts for an optional passphrase (hidden input) with confirmation. Returns `None` if
/// the user enters an empty passphrase.
pub fn prompt_new_passphrase() -> anyhow::Result<Option<Zeroizing<String>>> {
    let passphrase =
        prompt_password_hidden("Enter an optional passphrase (press Enter for none): ")?;
    if passphrase.is_empty() {
        return Ok(None);
    }
    let confirm = prompt_password_hidden("Confirm passphrase: ")?;
    if *passphrase != *confirm {
        anyhow::bail!("Passphrases do not match");
    }
    Ok(Some(passphrase))
}
