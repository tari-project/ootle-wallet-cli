// Copyright 2025 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use super::default_registries::get_default_registries;
use std::path::Path;
use tari_tapplet_lib::TappletRegistry;

/// Fetch all tapplet registries to the cache directory
pub async fn fetch_registries(cache_directory: &Path) -> anyhow::Result<()> {
    let default_registries = get_default_registries();

    println!("Fetching {} registries...", default_registries.len());

    for (name, url) in default_registries {
        println!("  Fetching '{}' from {}...", name, url);

        let registry_dir = cache_directory.join("registries");
        let mut registry = TappletRegistry::new(name, url, registry_dir);
        registry.fetch().await?;

        println!("    ✓ Fetched ({} tapplets)", registry.tapplets.len());
    }

    println!("✓ All registries fetched successfully");
    Ok(())
}
