// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Small helpers for interactive prompts during `setup`.

use std::io::{BufRead, Write};

use anyhow::Context;
use zeroize::Zeroizing;

fn read_trimmed_line<R: BufRead>(reader: &mut R) -> anyhow::Result<String> {
    let mut line = String::new();
    let bytes_read = reader
        .read_line(&mut line)
        .context("failed to read input")?;
    if bytes_read == 0 {
        anyhow::bail!("unexpected end of input while reading prompt");
    }
    Ok(line.trim().to_string())
}

fn read_password_line<R: BufRead>(reader: &mut R) -> anyhow::Result<Zeroizing<String>> {
    let mut line = Zeroizing::new(String::new());
    let bytes_read = reader
        .read_line(&mut line)
        .context("failed to read passphrase")?;
    if bytes_read == 0 {
        anyhow::bail!("unexpected end of input while reading passphrase");
    }
    if line.ends_with("\r\n") {
        let new_len = line.len() - 2;
        line.truncate(new_len);
    } else if line.ends_with('\n') || line.ends_with('\r') {
        let new_len = line.len() - 1;
        line.truncate(new_len);
    }
    Ok(line)
}

pub fn prompt_line(message: &str) -> anyhow::Result<String> {
    print!("{message}");
    std::io::stdout().flush()?;
    let stdin = std::io::stdin();
    let mut lock = stdin.lock();
    read_trimmed_line(&mut lock)
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
    let prompt = format!("{message} [{hint}]: ");
    loop {
        let input = prompt_line(&prompt)?;
        match input.to_lowercase().as_str() {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            other => {
                cli_println!(White, "Please answer 'y' or 'n', got '{}'", other);
            }
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
        print!("{message}");
        std::io::stdout().flush()?;
        let stdin = std::io::stdin();
        let mut lock = stdin.lock();
        read_password_line(&mut lock)
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn password_line_preserves_surrounding_whitespace() {
        let mut crlf = Cursor::new(b"  correct horse battery staple  \r\n");
        let pass = read_password_line(&mut crlf).unwrap();
        assert_eq!(&*pass, "  correct horse battery staple  ");

        let mut lf = Cursor::new(b"\tleading-tab\n");
        let pass_lf = read_password_line(&mut lf).unwrap();
        assert_eq!(&*pass_lf, "\tleading-tab");
    }

    #[test]
    fn trimmed_and_password_lines_reject_eof() {
        let mut empty = Cursor::new(b"");
        assert!(read_trimmed_line(&mut empty).is_err());

        let mut empty_pass = Cursor::new(b"");
        assert!(read_password_line(&mut empty_pass).is_err());
    }
}
