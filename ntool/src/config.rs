// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present ntool project and contributors.

//! Project configuration data.

#![allow(dead_code)]

/// Project name.
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// Project short description.
pub const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

/// Project code license.
pub const LICENSE: &str = env!("CARGO_PKG_LICENSE");

/// Project authors list.
pub const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

/// Project repository link.
pub const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");

/// Major release that indicates incompatible changes or significant updates.
pub const VERSION_MAJOR: &str = env!("CARGO_PKG_VERSION_MAJOR");

/// Minor release that indicates new features in a backward-compatible manner.
pub const VERSION_MINOR: &str = env!("CARGO_PKG_VERSION_MINOR");

/// Patch release that indicates bug fixes or minor improvements.
pub const VERSION_PATCH: &str = env!("CARGO_PKG_VERSION_PATCH");

/// Macro to create a version string from the version components.
macro_rules! version_string {
    () => {
        concat!(
            "v",
            env!("CARGO_PKG_VERSION_MAJOR"),
            ".",
            env!("CARGO_PKG_VERSION_MINOR"),
            ".",
            env!("CARGO_PKG_VERSION_PATCH")
        )
    };
}

/// Project version.
pub const VERSION: &str = version_string!();
