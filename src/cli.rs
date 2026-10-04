//! Defines the command-line arguments and subcommands parsed by the CLI.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "vault", version, about = "CLI password manager")]
pub struct Cli {
    /// Path to the vault file
    #[arg(long, global = true, default_value = "vault.json", value_name = "FILE")]
    pub file: PathBuf,

    /// Read passwords from stdin instead of the terminal
    #[arg(long, global = true)]
    pub stdin: bool,

    /// Emit JSON output for list and get
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Initialize a new vault
    Init,

    /// Add an entry
    Add {
        /// Site or service name
        #[arg(long)]
        site: String,

        /// Username for the site
        #[arg(long)]
        username: String,
    },

    /// Retrieve an entry's credentials
    Get {
        /// Site or service name
        site: String,
    },

    /// List all entries
    List,

    /// Remove an entry
    Remove {
        /// Site or service name
        site: String,
    },
}
