//! Cryptographic primitives: Argon2id key derivation and AES-256-GCM encryption.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

use crate::error::Error;

const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;

// Argon2id parameters (OWASP recommended minimums).
const M_COST: u32 = 19_456;
const T_COST: u32 = 2;
const P_COST: u32 = 1;

/// Generates a fresh random salt for key derivation.
pub fn generate_salt() -> [u8; SALT_LEN] {
    // Generate a random salt using the operating system's secure random number generator.
    let mut salt = [0_u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derives a 256-bit encryption key from the password and salt using Argon2id.
pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    // 1. Create Argon2id instance with recommended parameters
    // 2. Derive a 32-byte key from the password and salt
    // 3. Return the derived key wrapped in Zeroizing to ensure it is cleared from memory when dropped

    let params = Params::new(M_COST, T_COST, P_COST, Some(KEY_LEN))
        .map_err(|err| Error::Argon2(err.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new(vec![0_u8; KEY_LEN]);
    argon2
        .hash_password_into(password, salt, key.as_mut_slice())
        .map_err(|err| Error::Argon2(err.to_string()))?;
    Ok(key)
}

/// Encrypts plaintext with AES-256-GCM, returning the nonce and ciphertext.
pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    // 1. Create AES-256-GCM cipher instance with the derived key
    // 2. Generate a random 12-byte nonce
    // 3. Encrypt the plaintext using the cipher and nonce
    // 4. Return the nonce and ciphertext

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::InvalidKeyLength)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| Error::Encryption)?;

    Ok((nonce.to_vec(), ciphertext))
}

/// Decrypts AES-256-GCM ciphertext using the provided nonce.
pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    // 1. Create AES-256-GCM cipher instance with the derived key
    // 2. Decrypt the ciphertext using the cipher and nonce
    // 3. Return the plaintext

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::InvalidKeyLength)?;
    let nonce = Nonce::from_slice(nonce);
    cipher.decrypt(nonce, ciphertext).map_err(|_| Error::Encryption)
}
