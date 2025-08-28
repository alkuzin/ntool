// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present ntool project and contributors.

//! Ntool entry point.

mod cli;
mod config;

fn main() {
    let args = cli::parse();

    if args.version {
        cli::version();
    }
}
