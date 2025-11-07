// Copyright 2025 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Tapplet management module
//!
//! This module provides functionality for managing tapplets (Tari applets):
//! - Fetching tapplet registries
//! - Searching for tapplets
//! - Installing tapplets from registries or local paths
//! - Listing installed tapplets
//! - Uninstalling tapplets

mod default_registries;
mod fetch;
mod install;
mod list;
mod search;

pub use default_registries::get_default_registries;
pub use fetch::fetch_registries;
pub use install::{install_from_local, install_from_registry};
pub use list::list_installed_tapplets;
pub use search::search_tapplets;
