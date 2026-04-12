//! Explicit crypto wrappers.
//!
//! These helpers keep cryptographic choices in one place so future migrations
//! are deliberate rather than hidden in service code.

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::error::{PlatformError, Result};
use crate::secret::{SecretBytes, SecretString};

type HmacSha256 = Hmac<Sha256>;

/// Generate cryptographically secure random bytes.
pub fn random_bytes(length: usize) -> Result<Vec<u8>> {
    let mut output = vec![0_u8; length];
    getrandom::fill(&mut output).map_err(|error| {
        PlatformError::unavailable("failed to obtain secure randomness")
            .with_detail(error.to_string())
    })?;
    Ok(output)
}

/// Encode bytes using unpadded base64url.
pub fn base64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode unpadded base64url.
pub fn base64url_decode(value: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(value).map_err(|error| {
        PlatformError::invalid("invalid base64url data").with_detail(error.to_string())
    })
}

/// Compute a hex-encoded SHA-256 digest.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = core::fmt::Write::write_fmt(&mut output, format_args!("{byte:02x}"));
    }
    output
}

/// Compute an HMAC-SHA256 digest.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).map_err(|error| {
        PlatformError::invalid("invalid HMAC key").with_detail(error.to_string())
    })?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Hash a password using Argon2id with a random salt.
pub fn hash_password(password: &SecretString) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.expose().as_bytes(), &salt)
        .map(|value| value.to_string())
        .map_err(|error| {
            PlatformError::unavailable("failed to hash password").with_detail(error.to_string())
        })
}

/// Verify a password hash.
pub fn verify_password(password: &SecretString, encoded_hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(encoded_hash).map_err(|error| {
        PlatformError::invalid("invalid password hash").with_detail(error.to_string())
    })?;
    Ok(Argon2::default()
        .verify_password(password.expose().as_bytes(), &parsed)
        .is_ok())
}

/// Encrypt a secret using a symmetric key and random nonce.
pub fn seal_secret(key: &SecretBytes, plaintext: &SecretString) -> Result<String> {
    if key.expose().len() != 32 {
        return Err(PlatformError::invalid("secret key must be 32 bytes"));
    }

    let nonce_bytes = random_bytes(12)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.expose()));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            plaintext.expose().as_bytes(),
        )
        .map_err(|_| PlatformError::unavailable("failed to encrypt secret"))?;

    let mut combined = nonce_bytes;
    combined.extend_from_slice(&ciphertext);
    Ok(base64url_encode(&combined))
}

/// Decrypt a previously sealed secret.
pub fn unseal_secret(key: &SecretBytes, sealed: &str) -> Result<SecretString> {
    if key.expose().len() != 32 {
        return Err(PlatformError::invalid("secret key must be 32 bytes"));
    }

    let combined = base64url_decode(sealed)?;
    if combined.len() < 13 {
        return Err(PlatformError::invalid("sealed secret is too short"));
    }

    let (nonce, ciphertext) = combined.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.expose()));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| PlatformError::forbidden("failed to decrypt secret"))?;
    let text = String::from_utf8(plaintext).map_err(|error| {
        PlatformError::invalid("decrypted secret is not valid UTF-8").with_detail(error.to_string())
    })?;
    Ok(SecretString::new(text))
}
