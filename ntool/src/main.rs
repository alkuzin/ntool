// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present ntool project and contributors.

//! Ntool entry point.

use crate::cli::{Cli, Commands};
use clap::Parser;

mod cli;
mod config;

fn main() {
    let args = Cli::parse();

    if args.version {
        cli::version();
    }

    match &args.command {
        Commands::Ping {target, count} => {
            ntool_ping::ping(target, *count);
        }
    }
}
