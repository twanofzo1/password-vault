//! Reads passwords (from the terminal or stdin) and loads an existing vault.

use std::io;
use std::path::Path;

use zeroize::Zeroizing;

use vault::error::Error;
use vault::vault as store;
use vault::Vault;

/// Loads an existing vault after prompting for the master password.
pub fn load_existing(path: &Path, use_stdin: bool) -> Result<(Vault, Vec<u8>), Error> {
    // 1. Check if the vault file exists at the specified path
    // 2. If it does not exist, return a VaultNotFound error
    // 3. Prompt for the master password, reading from stdin or terminal as specified
    // 4. Call the store::load function to decrypt and deserialize the vault 
    // 5. return the Vault and salt on success, or an appropriate Error variant on failure

    if !path.exists() {
        return Err(Error::VaultNotFound(path.to_path_buf()));
    }

    let password = prompt_master_password(path, use_stdin)?;
    store::load(path, password.as_bytes())
}

/// Prompts for the master password, creating it first when the vault is new.
pub fn prompt_master_password(path: &Path, use_stdin: bool) -> Result<Zeroizing<String>, Error> {
    // 1. Check if the vault file exists at the specified path
    // 2. If it exists, prompt for the existing master password
    // 3. If it does not exist, prompt for a new master password and confirmation

    if path.exists() {
        read_master_password("Master password: ", use_stdin)
    } else {
        read_new_master_password(use_stdin)
    }
}

/// Reads and confirms a new master password.
pub fn read_new_master_password(use_stdin: bool) -> Result<Zeroizing<String>, Error> {
    // 1. Prompt for a new master password and confirmation, reading from stdin or terminal as specified
    // 2. If the two passwords do not match, return a PasswordMismatch error
    // 3. If the password is empty, return an EmptyPassword error
    // 4. Return the confirmed password wrapped in Zeroizing on success

    let first = read_master_password("Master password: ", use_stdin)?;
    let second = read_master_password("Confirm master password: ", use_stdin)?;

    if first.as_str() != second.as_str() {
        return Err(Error::PasswordMismatch);
    }

    Ok(first)
}

/// Reads one non-empty password from the terminal or stdin.
pub fn read_master_password(prompt: &str, use_stdin: bool) -> Result<Zeroizing<String>, Error> {
    // 1. Prompt for a password, reading from stdin or terminal as specified
    // 2. If the password is empty, return an EmptyPassword error
    // 3. Return the password wrapped in Zeroizing on success

    let password = if use_stdin {
        read_line_from_stdin()?
    } else {
        rpassword::prompt_password(prompt)?
    };

    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }

    Ok(Zeroizing::new(password))
}

/// Reads one line from stdin, stripping trailing line terminators in place.
fn read_line_from_stdin() -> Result<String, Error> {
    // 1. Read a line from stdin into a String
    // 2. Strip trailing line terminators in place
    // 3. Return the resulting String on success, or an I/O error on failure

    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}
