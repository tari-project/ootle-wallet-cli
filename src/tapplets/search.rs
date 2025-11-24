// Copyright 2025 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use super::default_registries::get_default_registries;
use anyhow::Context;
use serde::Deserialize;
use std::path::Path;
use tari_tapplet_lib::TappletConfig;

/// Search for tapplets matching the query string
pub async fn search_tapplets(
    query: &str,
    cache_directory: &Path,
) -> anyhow::Result<Vec<TappletConfig>> {
    let default_registries = get_default_registries();
    let mut results = Vec::new();

    for (name, _url) in default_registries {
        let registry_dir = cache_directory.join("registries").join(name);

        if !registry_dir.exists() {
            println!("Registry '{}' not found. Run 'tapplet fetch' first.", name);
            continue;
        }

        // Read all tapplet manifests in the registry
        let tapplets_dir = registry_dir.join("tapplets");
        if !tapplets_dir.exists() {
            continue;
        }

        for entry in std::fs::read_dir(&tapplets_dir).context(format!(
            "Failed to read tapplets directory: {:?}",
            tapplets_dir
        ))? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                let manifest_path = path.join("manifest.toml");
                if manifest_path.exists() {
                    let manifest_content = std::fs::read_to_string(&manifest_path)
                        .context(format!("Failed to read manifest: {:?}", manifest_path))?;

                    if let Ok(manifest) = toml::from_str::<TappletConfig>(&manifest_content) {
                        // Check if query matches name or description
                        let query_lower = query.to_lowercase();
                        let matches = manifest.name.to_lowercase().contains(&query_lower)
                            || manifest
                                .description
                                .as_ref()
                                .map(|d| d.to_lowercase().contains(&query_lower))
                                .unwrap_or(false);

                        if matches {
                            results.push(manifest);
                        }
                    }
                }
            }
        }
    }

    Ok(results)
}
