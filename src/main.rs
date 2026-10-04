#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::similar_names
)]

//! Command-line entry point for the vault password manager.

mod cli;
mod commands;
mod prompt;
mod query;

use std::process::ExitCode;

use clap::Parser;

use cli::Cli;
use commands::run;

/// Entry point: parses arguments and runs the selected command.
fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
