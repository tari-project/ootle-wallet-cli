// Copyright 2025 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use super::default_registries::get_default_registries;
use anyhow::Context;
use std::path::Path;

/// Fetch all tapplet registries to the cache directory
pub async fn fetch_registries(cache_directory: &Path) -> anyhow::Result<()> {
    let default_registries = get_default_registries();

    println!("Fetching {} registries...", default_registries.len());

    for (name, url) in default_registries {
        println!("  Fetching '{}' from {}...", name, url);

        // Create registry cache directory
        let registry_dir = cache_directory.join("registries").join(name);
        std::fs::create_dir_all(&registry_dir)
            .context(format!("Failed to create registry directory: {:?}", registry_dir))?;

        // Clone or update the git repository
        if registry_dir.join(".git").exists() {
            // Update existing repo
            let status = tokio::process::Command::new("git")
                .arg("-C")
                .arg(&registry_dir)
                .arg("pull")
                .status()
                .await
                .context("Failed to execute git pull")?;

            if !status.success() {
                anyhow::bail!("Failed to update registry '{}'", name);
            }
            println!("    ✓ Updated");
        } else {
            // Clone new repo
            let status = tokio::process::Command::new("git")
                .arg("clone")
                .arg(url)
                .arg(&registry_dir)
                .status()
                .await
                .context("Failed to execute git clone")?;

            if !status.success() {
                anyhow::bail!("Failed to clone registry '{}'", name);
            }
            println!("    ✓ Cloned");
        }
    }

    println!("✓ All registries fetched successfully");
    Ok(())
}
