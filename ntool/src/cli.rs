// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present ntool project and contributors.

//! CLI (Command-Line Interface) commands related declarations.

use crate::config::{DESCRIPTION, NAME, VERSION};
use clap::{Parser, Subcommand};
use chrono::Datelike;

#[derive(Parser)]
#[clap(about = DESCRIPTION)]
/// Command-line arguments struct.
pub struct Cli {
    /// Version flag.
    #[clap(short, long, help = "Display project version")]
    pub version: bool,
    /// Tool subcommand.
    #[clap(subcommand)]
    pub command: Commands,
}

/// Project CLI commands enumeration.
#[derive(Subcommand)]
pub enum Commands {
    #[clap(about = "Ping specific IP address/hostname")]
    Ping {
        #[clap(help = "Target IP address or hostname")]
        target: String,
        #[clap(short, long, help = "Number of pings", default_value_t = 4)]
        count: u8,
    },
}

/// Display project version.
pub fn version() {
    let year = chrono::Utc::now().year();
    let copyright =
        format!("Copyright (C) {year} ntool project and contributors.");

    println!("{} {} - {}.\n{}", NAME, VERSION, DESCRIPTION, copyright);
}
