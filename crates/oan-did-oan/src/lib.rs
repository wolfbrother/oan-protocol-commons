// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! `did:oan` profile-v2 parsing, generation, and validation.

use rand::{rngs::OsRng, RngCore};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::sync::OnceLock;
use thiserror::Error;

pub const DID_PREFIX: &str = "did:oan:";
pub const ROUTING_CODE_LEN: usize = 5;
pub const SUFFIX_CODE_LEN: usize = 32;
pub const DID_LEN: usize = 46;
pub const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn did_regex() -> &'static Regex {
    static DID_RE: OnceLock<Regex> = OnceLock::new();
    DID_RE.get_or_init(|| {
        Regex::new(r"^did:oan:[1-9A-HJ-NP-Za-km-z]{5}:[1-9A-HJ-NP-Za-km-z]{32}$").unwrap()
    })
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DidOanError {
    #[error("did must start with did:oan")]
    InvalidPrefix,
    #[error("did must have 4 colon-separated parts")]
    InvalidPartCount,
    #[error("routing-code must be exactly 5 case-sensitive Base58 characters")]
    InvalidRoutingCode,
    #[error("suffix-code must be exactly 32 Base58 characters")]
    InvalidSuffixCode,
    #[error("invalid did:oan profile-v2 syntax")]
    InvalidSyntax,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DidOan {
    value: String,
    routing_code: String,
    suffix_code: String,
}

impl DidOan {
    pub fn parse(value: impl AsRef<str>) -> Result<Self, DidOanError> {
        let value = value.as_ref();
        if !value.starts_with(DID_PREFIX) {
            return Err(DidOanError::InvalidPrefix);
        }
        let parts: Vec<&str> = value.split(':').collect();
        if parts.len() != 4 {
            return Err(DidOanError::InvalidPartCount);
        }
        let routing_code = parts[2];
        validate_routing_code(routing_code)?;
        let suffix_code = parts[3];
        validate_suffix_code(suffix_code)?;
        if !did_regex().is_match(value) {
            return Err(DidOanError::InvalidSyntax);
        }
        Ok(Self {
            value: value.to_owned(),
            routing_code: routing_code.to_owned(),
            suffix_code: suffix_code.to_owned(),
        })
    }

    pub fn generate(routing_code: &str) -> Result<Self, DidOanError> {
        validate_routing_code(routing_code)?;
        Self::parse(format!(
            "{DID_PREFIX}{routing_code}:{}",
            random_base58_suffix()
        ))
    }

    pub fn derive(
        routing_code: &str,
        controller_material: &[u8],
        nonce: &[u8],
    ) -> Result<Self, DidOanError> {
        validate_routing_code(routing_code)?;
        let mut hasher = Sha256::new();
        hasher.update(b"OAN-DID-SUFFIX-v2");
        hasher.update(routing_code.as_bytes());
        hasher.update(controller_material);
        hasher.update(nonce);
        Self::parse(format!(
            "{DID_PREFIX}{routing_code}:{}",
            derived_base58_suffix(hasher)
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }
    pub fn routing_code(&self) -> &str {
        &self.routing_code
    }
    pub fn suffix_code(&self) -> &str {
        &self.suffix_code
    }
    pub fn key_id(&self, fragment: &str) -> String {
        format!("{}#{}", self.value, fragment.trim_start_matches('#'))
    }
}

impl Display for DidOan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.value)
    }
}

impl FromStr for DidOan {
    type Err = DidOanError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

pub fn validate(value: &str) -> Result<(), DidOanError> {
    DidOan::parse(value).map(|_| ())
}

pub fn validate_routing_code(value: &str) -> Result<(), DidOanError> {
    if value.len() == ROUTING_CODE_LEN && value.chars().all(|ch| BASE58_ALPHABET.contains(ch)) {
        Ok(())
    } else {
        Err(DidOanError::InvalidRoutingCode)
    }
}

pub fn validate_suffix_code(value: &str) -> Result<(), DidOanError> {
    if value.len() == SUFFIX_CODE_LEN && value.chars().all(|ch| BASE58_ALPHABET.contains(ch)) {
        Ok(())
    } else {
        Err(DidOanError::InvalidSuffixCode)
    }
}

fn random_base58_suffix() -> String {
    let mut suffix = String::with_capacity(SUFFIX_CODE_LEN);
    let mut bytes = [0u8; 64];
    while suffix.len() < SUFFIX_CODE_LEN {
        OsRng.fill_bytes(&mut bytes);
        push_unbiased_base58_chars(&mut suffix, &bytes);
    }
    suffix.truncate(SUFFIX_CODE_LEN);
    suffix
}

fn derived_base58_suffix(seed_hasher: Sha256) -> String {
    let mut suffix = String::with_capacity(SUFFIX_CODE_LEN);
    let mut counter = 0u64;
    while suffix.len() < SUFFIX_CODE_LEN {
        let mut hasher = seed_hasher.clone();
        hasher.update(counter.to_be_bytes());
        push_unbiased_base58_chars(&mut suffix, hasher.finalize().as_slice());
        counter += 1;
    }
    suffix.truncate(SUFFIX_CODE_LEN);
    suffix
}

fn push_unbiased_base58_chars(output: &mut String, bytes: &[u8]) {
    let alphabet = BASE58_ALPHABET.as_bytes();
    let rejection_zone = u8::MAX - (u8::MAX % alphabet.len() as u8);
    for byte in bytes {
        if *byte < rejection_zone {
            output.push(alphabet[(*byte as usize) % alphabet.len()] as char);
            if output.len() == SUFFIX_CODE_LEN {
                break;
            }
        }
    }
}

