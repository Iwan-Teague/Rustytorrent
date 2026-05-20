//! Authenticated encryption + passphrase-derived keys for the B1
//! encrypted-spool storage mode. AES-256-GCM (RFC 5116) for the wire
//! format; Argon2id (RFC 9106) for key derivation.
//!
//! Threat model: the seized-laptop scenario. An attacker with the disk
//! image but not the user's passphrase should learn nothing about the
//! in-progress pieces. Speed matters too — disk-bound throughput
//! shouldn't drop below ~50 MB/s on modern hardware (AES-NI is
//! ubiquitous; `aes-gcm` uses it automatically).
//!
//! Two layers:
//! - `derive_key(passphrase, salt)` — Argon2id, parameters chosen for
//!   roughly half a second on a 2024-era laptop. Slow on purpose so
//!   brute-forcing the passphrase space is expensive.
//! - `encrypt` / `decrypt` — AEAD with a fresh random 12-byte nonce per
//!   call. The caller stores `(nonce, ciphertext_with_tag)` together;
//!   `aes-gcm` appends the 16-byte authentication tag to the
//!   ciphertext for us.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::Zeroize;

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32; // AES-256
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const SALT_LEN: usize = 16;

/// Argon2id parameters. 64 MiB memory, 3 passes, single-threaded — yields
/// somewhere around 400 ms on a 2024-era laptop. Tuned to deter brute
/// force without making startup feel broken. Recorded inline rather than
/// in the spool header so a future change can't silently downgrade an
/// existing spool's key strength.
const ARGON_MEMORY_KIB: u32 = 64 * 1024;
const ARGON_PASSES: u32 = 3;
const ARGON_PARALLELISM: u32 = 1;

/// Derive a 32-byte AES key from `passphrase` using Argon2id with the
/// fixed parameters above and the given `salt`. Pass the same salt back
/// in to reproduce the same key.
pub fn derive_key(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<[u8; KEY_LEN]> {
    let params = Params::new(
        ARGON_MEMORY_KIB,
        ARGON_PASSES,
        ARGON_PARALLELISM,
        Some(KEY_LEN),
    )
    .map_err(|e| Error::Crypto(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| Error::Crypto(format!("argon2 derive: {e}")))?;
    Ok(key)
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut s = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut n);
    n
}

/// Encrypt `plaintext` with `key` and a freshly generated nonce. Returns
/// `(nonce, ciphertext_with_tag)`. The ciphertext length is
/// `plaintext.len() + TAG_LEN`. Caller is responsible for storing the
/// nonce alongside the ciphertext (we never derive it from a counter so
/// the spool layout doesn't carry implicit ordering state).
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = random_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| Error::Crypto(format!("aes-gcm encrypt: {e}")))?;
    Ok((nonce_bytes, ct))
}

/// Decrypt `ciphertext` (which must include the trailing 16-byte tag)
/// with `key` and `nonce`. Returns the plaintext, or an error if the
/// tag check fails — typically meaning either the passphrase is wrong
/// or the spool was tampered with.
pub fn decrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher.decrypt(nonce, ciphertext).map_err(|e| {
        Error::Crypto(format!(
            "aes-gcm decrypt (wrong passphrase or tampered data?): {e}"
        ))
    })
}

/// A wiped-on-drop wrapper around the 32-byte AES key. Use this rather
/// than passing `[u8; 32]` by value through long-lived state.
pub struct SecretKey(pub [u8; KEY_LEN]);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_derivation_is_deterministic() {
        let salt = [0x11u8; SALT_LEN];
        let k1 = derive_key("hunter2", &salt).unwrap();
        let k2 = derive_key("hunter2", &salt).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn different_passphrase_gives_different_key() {
        let salt = [0x22u8; SALT_LEN];
        let k1 = derive_key("alpha", &salt).unwrap();
        let k2 = derive_key("beta", &salt).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn different_salt_gives_different_key() {
        let k1 = derive_key("same passphrase", &[0u8; SALT_LEN]).unwrap();
        let k2 = derive_key("same passphrase", &[1u8; SALT_LEN]).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let salt = random_salt();
        let key = derive_key("hunter2", &salt).unwrap();
        let plaintext = b"piece data that we want to keep off disk in plain form";
        let (nonce, ct) = encrypt(&key, plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len() + TAG_LEN);
        let back = decrypt(&key, &nonce, &ct).unwrap();
        assert_eq!(back, plaintext);
    }

    #[test]
    fn decrypt_rejects_wrong_key() {
        let salt = random_salt();
        let good = derive_key("right", &salt).unwrap();
        let bad = derive_key("wrong", &salt).unwrap();
        let (nonce, ct) = encrypt(&good, b"secret").unwrap();
        assert!(decrypt(&bad, &nonce, &ct).is_err());
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let salt = random_salt();
        let key = derive_key("k", &salt).unwrap();
        let (nonce, mut ct) = encrypt(&key, b"important").unwrap();
        // Flip one bit in the ciphertext — GCM tag check must catch it.
        ct[0] ^= 0x01;
        assert!(decrypt(&key, &nonce, &ct).is_err());
    }

    #[test]
    fn nonces_are_unique_per_encrypt_call() {
        let salt = random_salt();
        let key = derive_key("k", &salt).unwrap();
        let (n1, _) = encrypt(&key, b"x").unwrap();
        let (n2, _) = encrypt(&key, b"x").unwrap();
        assert_ne!(
            n1, n2,
            "nonces must not repeat — GCM is catastrophically insecure under reuse"
        );
    }
}
