// Copyright 2025 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::Context;
use std::path::Path;

/// List all installed tapplets
pub async fn list_installed_tapplets(cache_directory: &Path) -> anyhow::Result<Vec<String>> {
    let installed_dir = cache_directory.join("installed");

    if !installed_dir.exists() {
        return Ok(Vec::new());
    }

    let mut tapplets = Vec::new();

    for entry in std::fs::read_dir(&installed_dir)
        .context(format!("Failed to read installed directory: {:?}", installed_dir))?
    {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            if let Some(name) = path.file_name() {
                if let Some(name_str) = name.to_str() {
                    tapplets.push(name_str.to_string());
                }
            }
        }
    }

    tapplets.sort();
    Ok(tapplets)
}
