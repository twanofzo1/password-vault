//! Implements the mutating commands and dispatches subcommands from the CLI.

use std::path::Path;

use vault::crypto;
use vault::error::Error;
use vault::vault as store;
use vault::Vault;

use crate::cli::{Cli, Command};
use crate::prompt::{prompt_master_password, read_master_password, read_new_master_password};
use crate::query::{cmd_get, cmd_list};

/// Dispatches the parsed command to its handler.
pub fn run(cli: Cli) -> Result<(), Error> {
    // 1. Determine if stdin should be used for password input
    // 2. Determine if JSON output should be used for list and get commands
    // 3. Match on the command and call the appropriate handler function

    let use_stdin = cli.stdin;
    let json_output = cli.json;

    match cli.command {
        Command::Init                                   => cmd_init(&cli.file, use_stdin),
        Command::Add { site, username } => cmd_add(&cli.file, &site, &username, use_stdin),
        Command::Get { site }                   => cmd_get(&cli.file, &site, use_stdin, json_output),
        Command::List                                   => cmd_list(&cli.file, use_stdin, json_output),
        Command::Remove { site }                => cmd_remove(&cli.file, &site, use_stdin),
    }
}

/// Creates a new encrypted vault file.
fn cmd_init(path: &Path, use_stdin: bool) -> Result<(), Error> {
    // 1. check if vault file exists, if so return error
    // 2. prompt for new master password and confirmation
    // 3. generate salt and derive key from password
    // 4. create empty vault and save to file

    if path.exists() {
        return Err(Error::VaultExists(path.to_path_buf()));
    }

    let password = read_new_master_password(use_stdin)?;
    let salt = crypto::generate_salt();
    store::save(path, &Vault::default(), salt.as_slice(), password.as_bytes())?;

    println!("Vault initialized at {}", path.display());
    Ok(())
}

/// Adds a new entry to the vault.
fn cmd_add(path: &Path, site: &str, username: &str, use_stdin: bool) -> Result<(), Error> {
    // 1. check for master password and load vault or create new one if missing
    // 2. prompt for entry password
    // 3. add entry to vault and save
    // 4. print confirmation

    let password = prompt_master_password(path, use_stdin)?;
    let (mut vault, salt) = store::open_or_create(path, password.as_bytes())?;

    let entry_password =
        read_master_password(&format!("Password for {site} ({username}): "), use_stdin)?;
    vault.add(site, username, entry_password.as_str())?;
    store::save(path, &vault, salt.as_slice(), password.as_bytes())?;

    println!("Added {site}");
    Ok(())
}

/// Removes an entry from the vault.
fn cmd_remove(path: &Path, site: &str, use_stdin: bool) -> Result<(), Error> {
    // 1. check for master password and load vault or create new one if missing
    // 2. remove entry from vault and save
    // 3. print confirmation

    let password = prompt_master_password(path, use_stdin)?;
    let (mut vault, salt) = store::open_or_create(path, password.as_bytes())?;

    vault.remove(site)?;
    store::save(path, &vault, salt.as_slice(), password.as_bytes())?;

    println!("Removed {site}");
    Ok(())
}
