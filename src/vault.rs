//! Encrypted vault storage: the entry model plus file load and save operations.

use std::fs;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto;
use crate::error::Error;


const LINUX_FILE_PERMISSION_OWNER_ONLY: u32 = 0o600; // Read/write for owner only


#[derive(Debug, Serialize, Deserialize)]
pub struct Entry {
    pub site: String,
    pub username: String,
    pub password: String,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Vault {
    pub entries: Vec<Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultFile {
    version: u32,
    salt: String,
    nonce: String,
    ciphertext: String,
}

impl Vault {
    /// Adds a new entry, rejecting a duplicate site name.
    pub fn add(&mut self, site: &str, username: &str, password: &str) -> Result<(), Error> {
        // 1. Check if an entry with the same site already exists with the same username, returning an error if so
        // 2. Create a new Entry with the provided site, username, and password
        // 3. Push the new Entry into the entries vector
        
        if self.entries.iter().any(|entry| entry.site == site && entry.username == username) {
            return Err(Error::EntryExists(site.to_owned()));
        }

        self.entries.push(Entry {
            site: site.to_owned(),
            username: username.to_owned(),
            password: password.to_owned(),
        });

        Ok(())
    }

    /// Looks up an entry by its site name.
    pub fn get(&self, site: &str) -> Option<&Entry> {
        // iterate over the entries vector and find the first entry with a matching site
        self.entries.iter().find(|entry| entry.site == site)
    }

    /// Removes the entry for a site, erroring if it does not exist.
    pub fn remove(&mut self, site: &str) -> Result<(), Error> {
        // 1. Store the original length of the entries vector
        // 2. Retain only those entries whose site does not match the provided site
        // 3. If the length of the entries vector is unchanged, return an EntryNotFound error
        // 4. Otherwise, return Ok(())

        let original_len = self.entries.len();
        self.entries.retain(|entry| entry.site != site);

        if self.entries.len() == original_len {
            return Err(Error::EntryNotFound(site.to_owned()));
        }

        Ok(())
    }
}

/// Loads an existing vault, or starts a fresh in-memory one when the file is missing.
pub fn open_or_create(path: &Path, password: &[u8]) -> Result<(Vault, Vec<u8>), Error> {
    // 1. Check if the vault file exists at the specified path
    // 2. If it exists, call the load function to decrypt and deserialize the vault
    // 3. If it does not exist, return a new default Vault and a newly generated salt for key derivation

    if path.exists() {
        load(path, password)
    } else {
        Ok((Vault::default(), crypto::generate_salt().to_vec()))
    }
}

/// Decrypts and deserializes the vault at `path`, zeroizing the plaintext buffer.
pub fn load(path: &Path, password: &[u8]) -> Result<(Vault, Vec<u8>), Error> {
    // 1. Read the vault file from the specified path, returning an error if it does not exist
    // 2. Deserialize the JSON into a VaultFile struct
    // 3. Decode the base64-encoded salt, nonce, and ciphertext from the VaultFile
    // 4. Derive the encryption key from the password and salt using Argon2id
    // 5. Decrypt the ciphertext using AES-256-GCM with the derived key and nonce
    // 6. Deserialize the decrypted plaintext into a Vault struct

    let data = fs::read(path).map_err(|_| Error::VaultNotFound(path.to_path_buf()))?;
    let file: VaultFile = serde_json::from_slice(data.as_slice())?;

    let salt = STANDARD.decode(file.salt.as_bytes())?;
    let nonce = STANDARD.decode(file.nonce.as_bytes())?;
    let ciphertext = STANDARD.decode(file.ciphertext.as_bytes())?;

    let key = crypto::derive_key(password, salt.as_slice())?;
    let plaintext = Zeroizing::new(crypto::decrypt(
        key.as_slice(),
        nonce.as_slice(),
        ciphertext.as_slice(),
    )?);
    let vault: Vault = serde_json::from_slice(plaintext.as_slice())?;

    Ok((vault, salt))
}

/// Encrypts and writes the vault to `path`, restricting permissions on Unix.
pub fn save(path: &Path, vault: &Vault, salt: &[u8], password: &[u8]) -> Result<(), Error> {
    // 1. Derive the encryption key from the password and salt using Argon2id
    // 2. Serialize the Vault struct to JSON and wrap it in Zeroizing to clear the plaintext from memory when dropped
    // 3. Encrypt the JSON plaintext using AES-256-GCM with the derived key, generating a random nonce
    // 4. Encode the salt, nonce, and ciphertext to base64 and create a VaultFile struct
    // 5. Serialize the VaultFile to pretty JSON and write it to the specified path
    // 6. On Unix, set the file permissions to read/write for the owner only (0o600)

    let key = crypto::derive_key(password, salt)?;
    let plaintext = Zeroizing::new(serde_json::to_vec(vault)?);

    let (nonce, ciphertext) = crypto::encrypt(key.as_slice(), plaintext.as_slice())?;

    let file = VaultFile {
        version: 1,
        salt: STANDARD.encode(salt),
        nonce: STANDARD.encode(nonce.as_slice()),
        ciphertext: STANDARD.encode(ciphertext.as_slice()),
    };

    let json = serde_json::to_vec_pretty(&file)?;

    // Create the parent directory (and any missing ancestors) so writing a
    // vault to a fresh location such as ~/.vault/vault.json works on first run.
    if let Some(parent) = path.parent() && !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent)?;
    }

    fs::write(path, json)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(LINUX_FILE_PERMISSION_OWNER_ONLY))?;
    }

    Ok(())
}
