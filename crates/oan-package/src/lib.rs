// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! Verified package, manifest, and metadata models.

use chrono::{DateTime, Utc};
use oan_core::{
    CryptoSuite, DataIntegrityProof, DidDocument, ResourceType, ServiceEndpoint, SubjectType,
};
use oan_crypto::{hash_json_with_suite, CryptoError};
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
    #[error("package hash mismatch")]
    PackageHashMismatch,
    #[error("root proof claim mismatch")]
    RootProofClaimMismatch,
    #[error("resource type mismatch")]
    ResourceTypeMismatch,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceMetadata {
    #[serde(rename = "resourceDid")]
    pub resource_did: String,
    #[serde(rename = "resourceType")]
    pub resource_type: ResourceType,
    #[serde(rename = "subjectType")]
    pub subject_type: SubjectType,
    #[serde(rename = "publisherDid", skip_serializing_if = "Option::is_none")]
    pub publisher_did: Option<String>,
    #[serde(rename = "subjectDid", skip_serializing_if = "Option::is_none")]
    pub subject_did: Option<String>,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "capabilityTags", default)]
    pub capability_tags: Vec<String>,
    #[serde(rename = "authorizedDomains", default)]
    pub authorized_domains: Vec<String>,
    #[serde(rename = "protocolBindings", default)]
    pub protocol_bindings: Vec<serde_json::Value>,
    #[serde(default)]
    pub services: Vec<ServiceEndpoint>,
    #[serde(rename = "lifecycleState")]
    pub lifecycle_state: String,
    #[serde(rename = "packageVersion")]
    pub package_version: String,
    #[serde(rename = "packageHash")]
    pub package_hash: String,
    #[serde(rename = "metadataHash")]
    pub metadata_hash: String,
    #[serde(rename = "hashAlgorithm")]
    pub hash_algorithm: String,
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
    #[serde(rename = "packageClaims", skip_serializing_if = "Option::is_none")]
    pub package_claims: Option<serde_json::Value>,
    #[serde(rename = "proof", skip_serializing_if = "Option::is_none")]
    pub proof: Option<DataIntegrityProof>,
    #[serde(rename = "cryptoSuite", skip_serializing_if = "Option::is_none")]
    pub crypto_suite: Option<CryptoSuite>,
    #[serde(rename = "hashAlgorithm", skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePackageClaims {
    #[serde(rename = "resourceDid")]
    pub resource_did: String,
    #[serde(rename = "resourceType")]
    pub resource_type: ResourceType,
    pub version: String,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
    #[serde(rename = "metadataHash")]
    pub metadata_hash: String,
    #[serde(rename = "packageHash")]
    pub package_hash: String,
    #[serde(rename = "hashAlgorithm")]
    pub hash_algorithm: String,
    #[serde(rename = "lifecycleState")]
    pub lifecycle_state: String,
    #[serde(rename = "authorizedDomains", default)]
    pub authorized_domains: Vec<String>,
    #[serde(rename = "bulletinRef", skip_serializing_if = "Option::is_none")]
    pub bulletin_ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourcePackage {
    #[serde(rename = "packageVersion")]
    pub package_version: String,
    #[serde(rename = "resourceDid")]
    pub resource_did: String,
    #[serde(rename = "resourceType")]
    pub resource_type: ResourceType,
    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
    #[serde(rename = "metadataHash")]
    pub metadata_hash: String,
    #[serde(rename = "packageHash")]
    pub package_hash: String,
    #[serde(rename = "hashAlgorithm")]
    pub hash_algorithm: String,
    pub metadata: ResourceMetadata,
    #[serde(rename = "rootProof")]
    pub root_proof: RootProof,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

impl ResourcePackage {
    fn effective_crypto_suite(&self) -> CryptoSuite {
        self.root_proof
            .crypto_suite
            .clone()
            .or_else(|| {
                self.root_proof
                    .proof
                    .as_ref()
                    .and_then(|proof| proof.crypto_suite())
            })
            .unwrap_or(CryptoSuite::Ed25519Sha256)
    }

    pub fn verify_did_document_hash(&self) -> Result<(), PackageError> {
        let actual_hash = hash_json_with_suite(self.effective_crypto_suite(), &self.did_document)?;
        if hash_matches(&self.did_document_hash, &self.hash_algorithm, &actual_hash) {
            Ok(())
        } else {
            Err(PackageError::DidDocumentHashMismatch)
        }
    }

    pub fn verify_metadata_hash(&self) -> Result<(), PackageError> {
        let actual_hash =
            hash_resource_metadata_with_suite(self.effective_crypto_suite(), &self.metadata)?;
        if hash_matches(&self.metadata_hash, &self.hash_algorithm, &actual_hash) {
            Ok(())
        } else {
            Err(PackageError::MetadataHashMismatch)
        }
    }

    pub fn verify_package_hash(&self) -> Result<(), PackageError> {
        let actual_hash = hash_json_with_suite(
            self.effective_crypto_suite(),
            &serde_json::json!({
                "packageVersion": self.package_version,
                "resourceDid": self.resource_did,
                "resourceType": self.resource_type,
                "didDocumentHash": self.did_document_hash,
                "metadataHash": self.metadata_hash,
                "hashAlgorithm": self.hash_algorithm,
            }),
        )?;
        if hash_matches(&self.package_hash, &self.hash_algorithm, &actual_hash) {
            Ok(())
        } else {
            Err(PackageError::PackageHashMismatch)
        }
    }

    pub fn verify_resource_type_consistency(&self) -> Result<(), PackageError> {
        if self.resource_type == self.metadata.resource_type
            && resource_type_matches_subject(&self.resource_type, &self.metadata.subject_type)
        {
            Ok(())
        } else {
            Err(PackageError::ResourceTypeMismatch)
        }
    }

    pub fn verify_metadata_consistency(&self) -> Result<(), PackageError> {
        let did_document_domains = self
            .did_document
            .oan_metadata
            .as_ref()
            .map(|metadata| metadata.authorized_domains.as_slice())
            .unwrap_or_default();
        if self.metadata.resource_did == self.resource_did
            && self.metadata.package_version == self.package_version
            && self.metadata.package_hash == self.package_hash
            && self.metadata.metadata_hash == self.metadata_hash
            && self.metadata.hash_algorithm == self.hash_algorithm
            && did_document_domains == self.metadata.authorized_domains.as_slice()
        {
            Ok(())
        } else {
            Err(PackageError::RootProofClaimMismatch)
        }
    }

    pub fn verify_root_claim_binding(&self) -> Result<(), PackageError> {
        let Some(claims) = self.root_proof.package_claims.as_ref() else {
            return Err(PackageError::RootProofClaimMismatch);
        };
        let parsed: ResourcePackageClaims = serde_json::from_value(claims.clone())
            .map_err(|_| PackageError::RootProofClaimMismatch)?;

        if parsed.resource_did == self.resource_did
            && parsed.resource_type == self.resource_type
            && parsed.version == self.package_version
            && parsed.did_document_hash == self.did_document_hash
            && parsed.metadata_hash == self.metadata_hash
            && parsed.package_hash == self.package_hash
            && parsed.hash_algorithm == self.hash_algorithm
            && parsed.lifecycle_state == self.metadata.lifecycle_state
            && parsed.authorized_domains == self.metadata.authorized_domains
        {
            Ok(())
        } else {
            Err(PackageError::RootProofClaimMismatch)
        }
    }
}

fn resource_type_matches_subject(resource_type: &ResourceType, subject_type: &SubjectType) -> bool {
    matches!(
        (resource_type, subject_type),
        (ResourceType::AgentInstance, SubjectType::AgentInstance)
            | (ResourceType::AgentProduct, SubjectType::AgentProduct)
            | (ResourceType::AgentService, SubjectType::AgentService)
            | (ResourceType::AgentService, SubjectType::AgentInstance)
            | (ResourceType::Skill, SubjectType::Skill)
            | (ResourceType::McpServer, SubjectType::McpServer)
            | (ResourceType::ToolApi, SubjectType::ToolApi)
            | (ResourceType::Organization, SubjectType::Organization)
            | (ResourceType::Developer, SubjectType::Developer)
            | (
                ResourceType::InfrastructureNode,
                SubjectType::InfrastructureNode
            )
            | (ResourceType::RootNode, SubjectType::RootNode)
            | (ResourceType::RegistrarNode, SubjectType::RegistrarNode)
            | (ResourceType::DiscoveryNode, SubjectType::DiscoveryNode)
            | (ResourceType::CdnNode, SubjectType::CdnNode)
            | (ResourceType::VcIssuerNode, SubjectType::VcIssuerNode)
            | (
                ResourceType::TrustIndexerNode,
                SubjectType::TrustIndexerNode
            )
            | (ResourceType::Controller, SubjectType::Controller)
            | (ResourceType::Unspecified, SubjectType::Unspecified)
    )
}

pub fn hash_resource_metadata_with_suite(
    suite: CryptoSuite,
    metadata: &ResourceMetadata,
) -> Result<String, CryptoError> {
    let mut normalized = metadata.clone();
    normalized.metadata_hash.clear();
    normalized.package_hash.clear();
    hash_json_with_suite(suite, &normalized)
}

fn hash_matches(expected: &str, algorithm: &str, actual: &str) -> bool {
    expected == actual || expected == format!("{algorithm}:{actual}")
}

