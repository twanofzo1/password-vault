//! Implements the read-only commands that list and retrieve vault entries.

use std::path::Path;

use serde_json::{json, Value};

use vault::error::Error;

use crate::prompt::load_existing;

/// Prints the credentials stored for a site.
pub fn cmd_get(path: &Path, site: &str, use_stdin: bool, json_output: bool) -> Result<(), Error> {
    // 1. Load the existing vault from the specified path, prompting for the master password if necessary
    // 2. Look up the entry for the specified site, returning an error if not found
    // 3. If JSON output is requested, serialize the entry to JSON and print it, otherwise print the credentials in a human-readable format
    // 4. Return Ok(()) on success, or an appropriate Error variant on failure

    let (vault, _salt) = load_existing(path, use_stdin)?;
    let entry = vault
        .get(site)
        .ok_or_else(|| Error::EntryNotFound(site.to_owned()))?;

    if json_output {
        let value = json!({
            "site": entry.site.as_str(),
            "username": entry.username.as_str(),
            "password": entry.password.as_str(),
        });
        println!("{}", serde_json::to_string(&value)?);
    } else {
        println!("site: {}", entry.site);
        println!("username: {}", entry.username);
        println!("password: {}", entry.password);
    }

    Ok(())
}

/// Lists all entries stored in the vault.
pub fn cmd_list(path: &Path, use_stdin: bool, json_output: bool) -> Result<(), Error> {
    // 1. Load the existing vault from the specified path, prompting for the master password if necessary
    // 2. If JSON output is requested, serialize the list of entries to JSON and print it, otherwise print the entries in a human-readable format
    // 3. Return Ok(()) on success, or an error if the vault file does not exist or cannot be read

    let (vault, _salt) = load_existing(path, use_stdin)?;

    if json_output {
        let items: Vec<Value> = vault
            .entries
            .iter()
            .map(|entry| {
                json!({
                    "site": entry.site.as_str(),
                    "username": entry.username.as_str(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string(&Value::Array(items))?);
        return Ok(());
    }

    if vault.entries.is_empty() {
        println!("No entries.");
        return Ok(());
    }

    for entry in &vault.entries {
        println!("{}\t{}", entry.site, entry.username);
    }

    Ok(())
}
