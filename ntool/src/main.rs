// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present ntool project and contributors.

//! Ntool entry point.

use crate::cli::{Cli, Commands};
use clap::Parser;
use libc::getuid;

mod cli;
mod config;

fn main() {
    if !is_root() {
        println!("ntool: This process must be run as root");
        std::process::exit(1);
    }

    let args = Cli::parse();

    if args.version {
        cli::version();
    }

    if let Err(err) = handle_command(&args.command) {
        println!("ntool: {err}");
    }
}

/// Check whether this process is running under root.
///
/// # Return
/// - `true` - in case if this process is running under root.
/// - `false` - otherwise.
fn is_root() -> bool {
    unsafe { getuid() == 0 }
}

/// Handle CLI command.
///
/// # Parameters
/// - `command` - given CLI command to handle.
///
/// # Return
/// - `Ok` - in case of success.
/// - `Err` - otherwise.
fn handle_command(command: &Commands) -> Result<(), String> {
    match command {
        Commands::Ping { target, count } => {
            let ping_handler = ntool_ping::Ping::new()?;
            ping_handler.ping(target, *count)?;
        }
    }

    Ok(())
}
