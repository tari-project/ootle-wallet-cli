// Copyright 2025 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

/// Returns the default tapplet registries
pub fn get_default_registries() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Tari Official", "https://github.com/tari-project/tapplet-registry"),
    ]
}
