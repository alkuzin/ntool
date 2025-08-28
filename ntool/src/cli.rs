// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present ntool project and contributors.

//! CLI (Command-Line Interface) commands related declarations.

use crate::config::{DESCRIPTION, NAME, VERSION};
use chrono::Datelike;
use clap::Parser;

#[derive(Parser)]
#[clap(about = DESCRIPTION)]
/// Command-line arguments struct.
pub struct Cli {
    /// Version flag.
    #[clap(short, long, help = "Display project version")]
    pub version: bool,
}

/// Parse the command-line arguments.
///
/// # Return
/// - Parsed command-line arguments.
pub fn parse() -> Cli {
    let args = Cli::parse();
    args
}

/// Display project version.
pub fn version() {
    let year = chrono::Utc::now().year();
    let copyright =
        format!("Copyright (C) {year} ntool project and contributors.");

    println!("{} {} - {}.\n{}", NAME, VERSION, DESCRIPTION, copyright);
}
