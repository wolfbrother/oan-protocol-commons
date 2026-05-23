// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! Verified package, manifest, and metadata models.

use chrono::{DateTime, Utc};
use oan_core::DidDocument;
use oan_crypto::{hash_json, CryptoError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PackageError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("did document hash mismatch")]
    DidDocumentHashMismatch,
    #[error("metadata hash mismatch")]
    MetadataHashMismatch,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentMetadata {
    pub did: String,
    pub role: String,
    #[serde(rename = "identityType")]
    pub identity_type: String,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
    #[serde(rename = "capabilityTags", default)]
    pub capability_tags: Vec<String>,
    #[serde(default)]
    pub services: Vec<oan_core::ServiceEndpoint>,
    pub status: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootProof {
    #[serde(rename = "rootDid")]
    pub root_did: String,
    #[serde(rename = "bulletinEventHash")]
    pub bulletin_event_hash: Option<String>,
    pub signature: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerifiedPackage {
    #[serde(rename = "packageVersion")]
    pub package_version: String,
    pub did: String,
    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
    #[serde(
        rename = "metadataHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub metadata_hash: Option<String>,
    pub metadata: AgentMetadata,
    #[serde(rename = "rootProof")]
    pub root_proof: RootProof,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub did: String,
    pub role: String,
    #[serde(rename = "documentPath")]
    pub document_path: String,
    #[serde(rename = "metadataPath")]
    pub metadata_path: String,
    #[serde(rename = "packagePath")]
    pub package_path: String,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    #[serde(rename = "generatedAt")]
    pub generated_at: DateTime<Utc>,
    #[serde(rename = "rootDid")]
    pub root_did: String,
    pub packages: Vec<ManifestEntry>,
}

impl VerifiedPackage {
    pub fn verify_document_hash(&self) -> Result<(), PackageError> {
        let actual_hash = hash_json(&self.did_document)?;
        if actual_hash == self.did_document_hash {
            Ok(())
        } else {
            Err(PackageError::DidDocumentHashMismatch)
        }
    }

    pub fn verify_metadata_hash(&self) -> Result<(), PackageError> {
        let Some(expected_hash) = self.metadata_hash.as_deref() else {
            return Ok(());
        };
        let actual_hash = hash_json(&self.metadata)?;
        if actual_hash == expected_hash {
            Ok(())
        } else {
            Err(PackageError::MetadataHashMismatch)
        }
    }
}

