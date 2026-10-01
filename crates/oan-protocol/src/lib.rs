// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! Protocol models shared across OpenAgenet nodes.

use chrono::{DateTime, Utc};
use oan_core::{DataIntegrityProof, DidDocument, ResourceType, ServiceEndpoint};
use oan_did_oan::DidOan;
use oan_package::ResourcePackage;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const OAN_RESOURCE_PROTOCOL_VERSION: &str = "oan-resource-2026";
pub const PROTOCOL_VERSION: &str = OAN_RESOURCE_PROTOCOL_VERSION;
pub const PURPOSE_RESOURCE_REGISTRATION: &str = "resource-registration";
pub const PURPOSE_CONTROLLER_AUTHORIZATION_REGISTRATION: &str =
    "resource-registration-controller-authorization";
pub const PURPOSE_REGISTRATION_CREDENTIAL_QUERY: &str = "registration-credential-query";
pub const PROTOCOL_REGISTRATION_CREDENTIAL_QUERY_V1: &str = "oan-registration-credential-query-v1";
pub const PURPOSE_VERIFY_AND_PUBLISH: &str = "verify-and-publish";
pub const PURPOSE_CDN_PUBLISH: &str = "cdn-publish";
pub const PURPOSE_INFRASTRUCTURE_AUTHORIZATION_VC_ISSUE: &str =
    "infrastructure-authorization-vc-issue";
pub const PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH: &str = "/root/resources/verify-and-publish";
pub const PATH_ROOT_INFRASTRUCTURE_AUTHORIZATION_VCS_ISSUE: &str =
    "/root/infrastructure/authorization-vcs/issue";
pub const PATH_CDN_RESOURCES: &str = "/cdn/resources";
pub const PATH_CDN_RESOURCES_BATCH: &str = "/cdn/resources/batch";

/// Checks the current did:oan routing relationship for a resource submitted by a
/// registrar.  This is a syntactic admission check only; authorization and
/// lifecycle state remain governed by the existing proof and governance paths.
pub fn validate_resource_routing_code(
    resource_did: &str,
    registrar_did: &str,
) -> Result<(), String> {
    let resource = DidOan::parse(resource_did).map_err(|err| err.to_string())?;
    let registrar = DidOan::parse(registrar_did).map_err(|err| err.to_string())?;
    let expected = &registrar.suffix_code()[..5];
    if resource.routing_code() != expected {
        return Err("resource_routing_code_mismatch".to_owned());
    }
    Ok(())
}
pub const REGISTRATION_FLOW: &str = "did-control";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    #[serde(rename = "nodeType")]
    pub node_type: String,
    pub did: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NodeAuthorizeRequest {
    #[serde(rename = "nodeDid")]
    pub node_did: String,
    #[serde(rename = "nodeRole")]
    pub node_role: String,
    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryAuthorizeRequest {
    #[serde(rename = "discoveryDid")]
    pub discovery_did: String,
    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,
    pub endpoint: String,
    #[serde(rename = "authorizedDomains", default)]
    pub authorized_domains: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryDomainUpdateRequest {
    #[serde(rename = "discoveryDid")]
    pub discovery_did: String,
    #[serde(rename = "authorizedDomains")]
    pub authorized_domains: Vec<String>,
    #[serde(rename = "tagTreeVersion")]
    pub tag_tree_version: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceRegisterRequest {
    #[serde(rename = "resourceDid")]
    pub resource_did: String,
    #[serde(rename = "resourceType")]
    pub resource_type: ResourceType,
    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,
    pub metadata: Value,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedRequestEnvelope {
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub purpose: String,
    pub method: String,
    pub path: String,
    pub aud: String,
    #[serde(rename = "requestTimestamp")]
    pub request_timestamp: DateTime<Utc>,
    #[serde(rename = "requestNonce")]
    pub request_nonce: String,
    #[serde(rename = "bodyHash")]
    pub body_hash: String,
    pub proof: DataIntegrityProof,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DidControlChallenge {
    #[serde(rename = "challengeId")]
    pub challenge_id: String,
    #[serde(rename = "draftId")]
    pub draft_id: String,
    #[serde(rename = "subjectDid")]
    pub subject_did: String,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
    #[serde(rename = "registrarDid")]
    pub registrar_did: String,
    pub purpose: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    pub nonce: String,
    #[serde(rename = "issuedAt")]
    pub issued_at: DateTime<Utc>,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SubjectControlProofBundle {
    pub challenge: DidControlChallenge,
    pub proof: DataIntegrityProof,
    #[serde(rename = "verifiedAt", skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<DateTime<Utc>>,
    #[serde(
        rename = "verifiedVerificationMethod",
        skip_serializing_if = "Option::is_none"
    )]
    pub verified_verification_method: Option<String>,
    #[serde(rename = "proofHash", skip_serializing_if = "Option::is_none")]
    pub proof_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ControllerAuthorizationChallenge {
    #[serde(rename = "challengeId")]
    pub challenge_id: String,
    #[serde(rename = "resourceDid")]
    pub resource_did: String,
    #[serde(rename = "controllerDid")]
    pub controller_did: String,
    #[serde(rename = "publisherDid", skip_serializing_if = "Option::is_none")]
    pub publisher_did: Option<String>,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
    #[serde(rename = "metadataHash")]
    pub metadata_hash: String,
    #[serde(rename = "registrarDid")]
    pub registrar_did: String,
    pub purpose: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    pub nonce: String,
    #[serde(rename = "issuedAt")]
    pub issued_at: DateTime<Utc>,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ControllerAuthorizationProofBundle {
    pub challenge: ControllerAuthorizationChallenge,
    #[serde(rename = "controllerDidDocument")]
    pub controller_did_document: DidDocument,
    pub proof: DataIntegrityProof,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RegistrationCredentialQueryChallenge {
    pub method: String,
    pub path: String,
    #[serde(rename = "resourceDid")]
    pub resource_did: String,
    #[serde(rename = "controllerDid")]
    pub controller_did: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    pub purpose: String,
    #[serde(rename = "requestTimestamp")]
    pub request_timestamp: DateTime<Utc>,
    #[serde(rename = "requestNonce")]
    pub request_nonce: String,
    pub aud: String,
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    #[serde(rename = "bodyHash", skip_serializing_if = "Option::is_none")]
    pub body_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RegistrationCredentialQueryRequest {
    pub challenge: RegistrationCredentialQueryChallenge,
    #[serde(rename = "controllerDidDocument")]
    pub controller_did_document: DidDocument,
    pub proof: DataIntegrityProof,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RegistrationCredentialQueryResponse {
    #[serde(rename = "resourceDid")]
    pub resource_did: String,
    #[serde(rename = "controllerDid")]
    pub controller_did: String,
    #[serde(rename = "registrationCredential")]
    pub registration_credential: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceRegistrationSubmission {
    #[serde(rename = "resourceDid")]
    pub resource_did: String,
    #[serde(rename = "resourceType")]
    pub resource_type: ResourceType,
    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
    pub metadata: Value,
    #[serde(rename = "packageVersion")]
    pub package_version: String,
    #[serde(rename = "packageHash")]
    pub package_hash: String,
    #[serde(rename = "metadataHash")]
    pub metadata_hash: String,
    #[serde(rename = "hashAlgorithm")]
    pub hash_algorithm: String,
    #[serde(
        rename = "registrationCredential",
        default,
        skip_serializing_if = "Value::is_null"
    )]
    pub registration_credential: Value,
    #[serde(rename = "subjectControlProof")]
    pub subject_control_proof: SubjectControlProofBundle,
    #[serde(
        rename = "controllerAuthorizationProof",
        skip_serializing_if = "Option::is_none"
    )]
    pub controller_authorization_proof: Option<ControllerAuthorizationProofBundle>,
}

impl ResourceRegistrationSubmission {
    pub fn validate_shape(&self) -> Result<(), String> {
        let did = DidOan::parse(&self.resource_did).map_err(|err| err.to_string())?;
        let _ = did;
        if self.did_document.id != self.resource_did {
            return Err("did_document_id_mismatch".to_owned());
        }
        self.did_document
            .validate_oan_resource()
            .map_err(|err| err.to_string())?;
        if self
            .did_document
            .oan_metadata
            .as_ref()
            .map(|metadata| metadata.resource_type != self.resource_type)
            .unwrap_or(true)
        {
            return Err("resource_type_mismatch".to_owned());
        }
        if self.package_version.trim().is_empty() {
            return Err("empty_package_version".to_owned());
        }
        if self.hash_algorithm.trim().is_empty() {
            return Err("empty_hash_algorithm".to_owned());
        }
        validate_hash_reference(
            "did_document_hash",
            &self.did_document_hash,
            &self.hash_algorithm,
        )?;
        validate_hash_reference("metadata_hash", &self.metadata_hash, &self.hash_algorithm)?;
        validate_hash_reference("package_hash", &self.package_hash, &self.hash_algorithm)?;
        let challenge = &self.subject_control_proof.challenge;
        if challenge.subject_did != self.resource_did {
            return Err("challenge_subject_did_mismatch".to_owned());
        }
        if challenge.did_document_hash != self.did_document_hash {
            return Err("challenge_did_document_hash_mismatch".to_owned());
        }
        if challenge.purpose != PURPOSE_RESOURCE_REGISTRATION {
            return Err("challenge_purpose_mismatch".to_owned());
        }
        if let Some(bundle) = &self.controller_authorization_proof {
            let controller_challenge = &bundle.challenge;
            if controller_challenge.resource_did != self.resource_did {
                return Err("controller_authorization_resource_did_mismatch".to_owned());
            }
            if controller_challenge.did_document_hash != self.did_document_hash {
                return Err("controller_authorization_did_document_hash_mismatch".to_owned());
            }
            if controller_challenge.metadata_hash != self.metadata_hash {
                return Err("controller_authorization_metadata_hash_mismatch".to_owned());
            }
            if controller_challenge.purpose != PURPOSE_CONTROLLER_AUTHORIZATION_REGISTRATION {
                return Err("controller_authorization_purpose_mismatch".to_owned());
            }
            if bundle.controller_did_document.id != controller_challenge.controller_did {
                return Err("controller_authorization_did_document_id_mismatch".to_owned());
            }
        }
        Ok(())
    }
}


fn validate_hash_reference(field_name: &str, value: &str, algorithm: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("empty_{field_name}"));
    }
    let expected_prefix = format!("{algorithm}:");
    if value.contains(':') && !value.starts_with(&expected_prefix) {
        return Err(format!("{field_name}_algorithm_mismatch"));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceVerifyAndPublishRequest {
    #[serde(rename = "registrarDid")]
    pub registrar_did: String,
    pub submission: ResourceRegistrationSubmission,
    #[serde(rename = "didDocumentRaw", default, skip_serializing_if = "Option::is_none")]
    pub did_document_raw: Option<Value>,
    #[serde(rename = "upstreamAuth")]
    pub upstream_auth: SignedRequestEnvelope,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceCdnPublishRequest {
    pub package: ResourcePackage,
    #[serde(rename = "upstreamAuth")]
    pub upstream_auth: SignedRequestEnvelope,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceCdnPublishBatchItem {
    #[serde(rename = "publicationCursor")]
    pub publication_cursor: i64,
    pub package: ResourcePackage,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceCdnBatchPublishRequest {
    pub items: Vec<ResourceCdnPublishBatchItem>,
    #[serde(rename = "upstreamAuth")]
    pub upstream_auth: SignedRequestEnvelope,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceCdnIndexItem {
    pub cursor: i64,
    pub package: ResourcePackage,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceCdnIndexResponse {
    pub items: Vec<ResourceCdnIndexItem>,
    pub count: usize,
    #[serde(rename = "afterCursor")]
    pub after_cursor: i64,
    #[serde(rename = "nextCursor")]
    pub next_cursor: i64,
    #[serde(rename = "hasMore")]
    pub has_more: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaginationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PaginationResponse<T> {
    pub items: Vec<T>,
    pub count: usize,
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(rename = "hasMore")]
    pub has_more: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RootAuthorizeRequest {
    #[serde(rename = "targetDid")]
    pub target_did: String,
    #[serde(rename = "targetRole")]
    pub target_role: String,
    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InfrastructureAuthorizationVcIssuePayload {
    #[serde(rename = "subjectDid")]
    pub subject_did: String,
    pub role: String,
    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,
    #[serde(rename = "didDocumentStableHash")]
    pub did_document_stable_hash: String,
    #[serde(rename = "authorizedDomains", default)]
    pub authorized_domains: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InfrastructureAuthorizationVcIssueRequest {
    pub payload: InfrastructureAuthorizationVcIssuePayload,
    #[serde(rename = "upstreamAuth")]
    pub upstream_auth: SignedRequestEnvelope,
}

pub type DiscoveryResponseProof = DataIntegrityProof;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceDiscoveryQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(rename = "resourceType", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<ResourceType>,
    #[serde(rename = "capabilityTags", default)]
    pub capability_tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "versionMode", default = "default_version_mode")]
    pub version_mode: String,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    10
}

fn default_version_mode() -> String {
    "latest".to_owned()
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceDiscoveryCandidate {
    #[serde(rename = "resourceDid")]
    pub resource_did: String,
    #[serde(rename = "resourceType")]
    pub resource_type: ResourceType,
    pub score: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "lifecycleState", skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<String>,
    #[serde(rename = "capabilityTags", default)]
    pub capability_tags: Vec<String>,
    #[serde(rename = "authorizedDomains", default)]
    pub authorized_domains: Vec<String>,
    #[serde(default)]
    pub services: Vec<ServiceEndpoint>,
    #[serde(rename = "protocolBindings", default)]
    pub protocol_bindings: Vec<Value>,
    #[serde(rename = "packageInfo", skip_serializing_if = "Option::is_none")]
    pub package_info: Option<Value>,
    #[serde(rename = "rootProof", skip_serializing_if = "Option::is_none")]
    pub root_proof: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceDiscoveryResponse {
    #[serde(rename = "discoveryDid")]
    pub discovery_did: String,
    pub candidates: Vec<ResourceDiscoveryCandidate>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    pub proof: Option<DiscoveryResponseProof>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRootDiscoveryNotificationItem {
    #[serde(rename = "resourceDid")]
    pub resource_did: String,
    #[serde(rename = "resourceType")]
    pub resource_type: ResourceType,
    pub operation: String,
    #[serde(rename = "packageVersion")]
    pub package_version: String,
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
    #[serde(rename = "bulletinSequence")]
    pub bulletin_sequence: u64,
    #[serde(rename = "bulletinEventHash")]
    pub bulletin_event_hash: String,
    #[serde(rename = "capabilityTags", default)]
    pub capability_tags: Vec<String>,
    #[serde(rename = "authorizedDomains", default)]
    pub authorized_domains: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceRootDiscoveryBatchNotification {
    #[serde(rename = "notificationBatchId")]
    pub notification_batch_id: String,
    #[serde(rename = "rootDid")]
    pub root_did: String,
    #[serde(rename = "targetDiscoveryDid")]
    pub target_discovery_did: String,
    #[serde(rename = "authorizedDomains", default)]
    pub authorized_domains: Vec<String>,
    #[serde(rename = "sequenceFrom")]
    pub sequence_from: u64,
    #[serde(rename = "sequenceTo")]
    pub sequence_to: u64,
    pub items: Vec<ResourceRootDiscoveryNotificationItem>,
    #[serde(rename = "cdnManifestUrl")]
    pub cdn_manifest_url: String,
    #[serde(rename = "cdnUpdatesUrl")]
    pub cdn_updates_url: String,
    pub proof: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InvocationEnvelope {
    pub id: String,
    #[serde(rename = "callerDid")]
    pub caller_did: String,
    #[serde(rename = "targetDid")]
    pub target_did: String,
    pub protocol: String,
    pub payload: Value,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    pub signature: String,
}

