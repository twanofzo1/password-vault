//! Error type shared across the vault library.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("base64 error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Argon2 error: {0}")]
    Argon2(String),

    #[error("encryption or decryption failed")]
    Encryption,

    #[error("invalid key length")]
    InvalidKeyLength,

    #[error("passwords do not match")]
    PasswordMismatch,

    #[error("password cannot be empty")]
    EmptyPassword,

    #[error("vault already exists at {0}")]
    VaultExists(PathBuf),

    #[error("vault not found at {0}")]
    VaultNotFound(PathBuf),

    #[error("entry '{0}' not found")]
    EntryNotFound(String),

    #[error("entry '{0}' already exists")]
    EntryExists(String),
}
