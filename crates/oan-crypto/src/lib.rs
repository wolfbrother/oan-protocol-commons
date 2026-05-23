// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! Cryptographic helpers for OpenAgenet.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid ed25519 signing key")]
    InvalidSigningKey,
    #[error("invalid ed25519 verifying key")]
    InvalidVerifyingKey,
    #[error("invalid public key encoding")]
    InvalidPublicKeyEncoding,
    #[error("invalid ed25519 signature")]
    InvalidSignature,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub fn generate_ed25519_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, CryptoError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidSigningKey)?;
    Ok(SigningKey::from_bytes(&bytes))
}

pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, CryptoError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidVerifyingKey)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::InvalidVerifyingKey)
}

pub fn verifying_key_from_public_key_multibase(
    public_key_multibase: &str,
) -> Result<VerifyingKey, CryptoError> {
    let encoded = public_key_multibase
        .strip_prefix('z')
        .ok_or(CryptoError::InvalidPublicKeyEncoding)?;
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| CryptoError::InvalidPublicKeyEncoding)?;
    verifying_key_from_bytes(&bytes)
}

pub fn verifying_key_from_public_key_jwk(
    public_key_jwk: &serde_json::Value,
) -> Result<VerifyingKey, CryptoError> {
    let x = public_key_jwk
        .get("x")
        .and_then(|value| value.as_str())
        .ok_or(CryptoError::InvalidPublicKeyEncoding)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| CryptoError::InvalidPublicKeyEncoding)?;
    verifying_key_from_bytes(&bytes)
}

pub fn sign_bytes(signing_key: &SigningKey, payload: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(signing_key.sign(payload).to_bytes())
}

pub fn verify_bytes(
    verifying_key: &VerifyingKey,
    payload: &[u8],
    signature_base64url: &str,
) -> Result<(), CryptoError> {
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_base64url)
        .map_err(|_| CryptoError::InvalidSignature)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| CryptoError::InvalidSignature)?;
    verifying_key
        .verify(payload, &signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

pub fn sha256_hex(payload: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(payload.as_ref()))
}

pub fn canonical_json<T: Serialize>(value: &T) -> Result<String, CryptoError> {
    let value = serde_json::to_value(value)?;
    Ok(canonical_json_value(&value))
}

pub fn hash_json<T: Serialize>(value: &T) -> Result<String, CryptoError> {
    Ok(sha256_hex(canonical_json(value)?))
}

pub fn public_key_multibase(verifying_key: &VerifyingKey) -> String {
    format!("z{}", bs58::encode(verifying_key.as_bytes()).into_string())
}

pub fn canonical_json_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_owned(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::String(value) => {
            serde_json::to_string(value).expect("string serialization cannot fail")
        }
        serde_json::Value::Array(values) => {
            let items = values
                .iter()
                .map(canonical_json_value)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{items}]")
        }
        serde_json::Value::Object(map) => {
            let items = map
                .iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("key serialization cannot fail"),
                        canonical_json_value(value)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{items}}}")
        }
    }
}

