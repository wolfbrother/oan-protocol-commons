// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! Core domain types shared by OAN services.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoSuite {
    #[serde(alias = "Ed25519Sha256Legacy")]
    Ed25519Sha256Legacy,
    #[serde(alias = "Ed25519Sha256")]
    Ed25519Sha256,
    #[serde(alias = "Sm2Sm3")]
    Sm2Sm3,
}

impl CryptoSuite {
    pub fn signing_algorithm(&self) -> &'static str {
        match self {
            Self::Ed25519Sha256Legacy | Self::Ed25519Sha256 => "Ed25519",
            Self::Sm2Sm3 => "SM2",
        }
    }

    pub fn hash_algorithm(&self) -> &'static str {
        match self {
            Self::Ed25519Sha256Legacy | Self::Ed25519Sha256 => "SHA-256",
            Self::Sm2Sm3 => "SM3",
        }
    }

    /// Canonical profile-v2 spelling used in serialized proofs.
    pub fn canonical_hash_algorithm(&self) -> &'static str {
        match self {
            Self::Ed25519Sha256Legacy | Self::Ed25519Sha256 => "sha256",
            Self::Sm2Sm3 => "sm3",
        }
    }

    pub fn verification_method_type(&self) -> &'static str {
        match self {
            Self::Ed25519Sha256Legacy | Self::Ed25519Sha256 => "Ed25519VerificationKey2020",
            Self::Sm2Sm3 => "SM2VerificationKey2020",
        }
    }

    pub fn proof_type(&self) -> &'static str {
        match self {
            Self::Ed25519Sha256Legacy | Self::Ed25519Sha256 => "Ed25519Signature2020",
            Self::Sm2Sm3 => "SM2Signature2020",
        }
    }

    pub fn from_verification_method_type(value: &str) -> Option<Self> {
        match value {
            "Ed25519VerificationKey2020" => Some(Self::Ed25519Sha256Legacy),
            "SM2VerificationKey2020" => Some(Self::Sm2Sm3),
            _ => None,
        }
    }

    pub fn from_proof_type(value: &str) -> Option<Self> {
        match value {
            "Ed25519Signature2020" => Some(Self::Ed25519Sha256Legacy),
            "SM2Signature2020" => Some(Self::Sm2Sm3),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectType {
    AgentInstance,
    AgentProduct,
    RootNode,
    RegistrarNode,
    DiscoveryNode,
    CdnNode,
    VcIssuerNode,
    TrustIndexerNode,
    Unspecified,
    #[serde(skip)]
    Agent,
    AgentService,
    Skill,
    McpServer,
    ToolApi,
    Organization,
    Developer,
    InfrastructureNode,
    Controller,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    AgentInstance,
    AgentProduct,
    AgentService,
    Skill,
    McpServer,
    ToolApi,
    InfrastructureNode,
    Organization,
    Developer,
    RootNode,
    RegistrarNode,
    DiscoveryNode,
    CdnNode,
    VcIssuerNode,
    TrustIndexerNode,
    Unspecified,
    Controller,
}

impl ResourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AgentInstance => "agent_instance",
            Self::AgentProduct => "agent_product",
            Self::AgentService => "agent_service",
            Self::Skill => "skill",
            Self::McpServer => "mcp_server",
            Self::ToolApi => "tool_api",
            Self::InfrastructureNode => "infrastructure_node",
            Self::Organization => "organization",
            Self::Developer => "developer",
            Self::RootNode => "root_node",
            Self::RegistrarNode => "registrar_node",
            Self::DiscoveryNode => "discovery_node",
            Self::CdnNode => "cdn_node",
            Self::VcIssuerNode => "vc_issuer_node",
            Self::TrustIndexerNode => "trust_indexer_node",
            Self::Unspecified => "unspecified",
            Self::Controller => "controller",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeRole {
    Root,
    Registrar,
    Discovery,
    ServiceAgent,
    UserAgent,
    TestAgent,
}

impl NodeRole {
    pub fn subject_type(&self) -> SubjectType {
        match self {
            Self::ServiceAgent | Self::UserAgent | Self::TestAgent => SubjectType::Agent,
            Self::Root | Self::Registrar | Self::Discovery => SubjectType::InfrastructureNode,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub controller: String,
    #[serde(rename = "cryptoSuite", skip_serializing_if = "Option::is_none")]
    pub crypto_suite: Option<CryptoSuite>,
    #[serde(rename = "publicKeyFormat", skip_serializing_if = "Option::is_none")]
    pub public_key_format: Option<String>,
    #[serde(rename = "publicKeyMultibase", skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<serde_json::Value>,
}

impl VerificationMethod {
    pub fn crypto_suite(&self) -> Option<CryptoSuite> {
        self.crypto_suite
            .clone()
            .or_else(|| CryptoSuite::from_verification_method_type(&self.method_type))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataIntegrityProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub creator: String,
    pub created: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
    #[serde(rename = "cryptoSuite", skip_serializing_if = "Option::is_none")]
    pub crypto_suite: Option<CryptoSuite>,
    #[serde(rename = "hashAlgorithm", skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,
    #[serde(rename = "verificationMethod", skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<String>,
}

impl DataIntegrityProof {
    pub fn crypto_suite(&self) -> Option<CryptoSuite> {
        self.crypto_suite
            .clone()
            .or_else(|| CryptoSuite::from_proof_type(&self.proof_type))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(rename = "serverType", skip_serializing_if = "Option::is_none")]
    pub server_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressBinding {
    pub id: String,
    #[serde(rename = "addressType")]
    pub address_type: String,
    pub network: String,
    pub address: String,
    pub controller: String,
    pub purpose: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AgentDescription {
    #[serde(rename = "capabilityDescription")]
    pub capability_description: String,
    #[serde(rename = "capabilityTags", default)]
    pub capability_tags: Vec<String>,
    #[serde(rename = "useCaseExamples", default)]
    pub use_case_examples: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ResourceDescription {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(
        rename = "capabilityDescription",
        skip_serializing_if = "Option::is_none"
    )]
    pub capability_description: Option<String>,
    #[serde(rename = "capabilityTags", default)]
    pub capability_tags: Vec<String>,
    #[serde(rename = "useCaseExamples", default)]
    pub use_case_examples: Vec<String>,
    #[serde(rename = "inputSchema", skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<serde_json::Value>,
    #[serde(rename = "outputSchema", skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub examples: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolBinding {
    pub id: String,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(rename = "serviceRef", skip_serializing_if = "Option::is_none")]
    pub service_ref: Option<String>,
    #[serde(rename = "schemaRef", skip_serializing_if = "Option::is_none")]
    pub schema_ref: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImplementationLink {
    pub relation: String,
    #[serde(rename = "targetDid")]
    pub target_did: String,
    #[serde(rename = "targetType", skip_serializing_if = "Option::is_none")]
    pub target_type: Option<ResourceType>,
    #[serde(rename = "targetService", skip_serializing_if = "Option::is_none")]
    pub target_service: Option<String>,
    #[serde(rename = "versionConstraint", skip_serializing_if = "Option::is_none")]
    pub version_constraint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRequirement {
    #[serde(rename = "credentialType")]
    pub credential_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<serde_json::Value>,
    #[serde(rename = "presentationMode", skip_serializing_if = "Option::is_none")]
    pub presentation_mode: Option<String>,
    #[serde(default)]
    pub required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageInfo {
    #[serde(rename = "manifestUrl", skip_serializing_if = "Option::is_none")]
    pub manifest_url: Option<String>,
    #[serde(rename = "downloadUrl", skip_serializing_if = "Option::is_none")]
    pub download_url: Option<String>,
    #[serde(rename = "packageHash", skip_serializing_if = "Option::is_none")]
    pub package_hash: Option<String>,
    #[serde(rename = "metadataHash", skip_serializing_if = "Option::is_none")]
    pub metadata_hash: Option<String>,
    #[serde(rename = "rootProofRef", skip_serializing_if = "Option::is_none")]
    pub root_proof_ref: Option<String>,
    #[serde(rename = "bulletinRef", skip_serializing_if = "Option::is_none")]
    pub bulletin_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "versionScheme", skip_serializing_if = "Option::is_none")]
    pub version_scheme: Option<String>,
    #[serde(rename = "previousVersion", skip_serializing_if = "Option::is_none")]
    pub previous_version: Option<String>,
    #[serde(rename = "releaseNotesUrl", skip_serializing_if = "Option::is_none")]
    pub release_notes_url: Option<String>,
    #[serde(rename = "createdAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(rename = "updatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OanMetadata {
    #[serde(rename = "subjectType")]
    pub subject_type: SubjectType,
    #[serde(rename = "resourceType")]
    pub resource_type: ResourceType,
    #[serde(
        rename = "externalIdentifiers",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub external_identifiers: Vec<ExternalIdentifier>,
    #[serde(rename = "identityType", skip_serializing_if = "Option::is_none")]
    pub identity_type: Option<String>,
    #[serde(rename = "controllerDid", skip_serializing_if = "Option::is_none")]
    pub controller_did: Option<String>,
    #[serde(rename = "publisherDid", skip_serializing_if = "Option::is_none")]
    pub publisher_did: Option<String>,
    #[serde(rename = "issuerDid", skip_serializing_if = "Option::is_none")]
    pub issuer_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    #[serde(
        rename = "resourceDescription",
        skip_serializing_if = "Option::is_none"
    )]
    pub resource_description: Option<ResourceDescription>,
    #[serde(rename = "agentDescription", skip_serializing_if = "Option::is_none")]
    pub agent_description: Option<AgentDescription>,
    #[serde(rename = "capabilityTags", default)]
    pub capability_tags: Vec<String>,
    #[serde(rename = "authorizedDomains", default)]
    pub authorized_domains: Vec<String>,
    #[serde(rename = "protocolBindings", default)]
    pub protocol_bindings: Vec<ProtocolBinding>,
    #[serde(rename = "implementationLinks", default)]
    pub implementation_links: Vec<ImplementationLink>,
    #[serde(rename = "credentialRequirements", default)]
    pub credential_requirements: Vec<CredentialRequirement>,
    #[serde(rename = "packageInfo", skip_serializing_if = "Option::is_none")]
    pub package_info: Option<PackageInfo>,
    #[serde(rename = "servicePolicy", skip_serializing_if = "Option::is_none")]
    pub service_policy: Option<String>,
    #[serde(rename = "networkScope", skip_serializing_if = "Option::is_none")]
    pub network_scope: Option<String>,
    #[serde(rename = "lifecycleState", skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<DidController>,
    #[serde(rename = "verificationMethod", default)]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(default)]
    pub authentication: Vec<String>,
    #[serde(rename = "assertionMethod", default)]
    pub assertion_method: Vec<String>,
    #[serde(
        rename = "capabilityInvocation",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub capability_invocation: Vec<String>,
    #[serde(default)]
    pub service: Vec<ServiceEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<DataIntegrityProof>,
    #[serde(rename = "oanMetadata", skip_serializing_if = "Option::is_none")]
    pub oan_metadata: Option<OanMetadata>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalIdentifier {
    pub id: String,
    #[serde(
        rename = "resolutionServiceEndpoint",
        skip_serializing_if = "Option::is_none"
    )]
    pub resolution_service_endpoint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DidController {
    Did(String),
    Dids(Vec<String>),
}

impl DidController {
    pub fn contains(&self, did: &str) -> bool {
        match self {
            Self::Did(value) => value == did,
            Self::Dids(values) => values.iter().any(|value| value == did),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityTag {
    pub id: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityTreeNode {
    pub id: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<CapabilityTreeNode>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityTagTree {
    pub version: u64,
    #[serde(default)]
    pub tags: Vec<CapabilityTag>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tree: Vec<CapabilityTreeNode>,
}

impl CapabilityTagTree {
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, oan_storage::StorageError> {
        let store = oan_storage::JsonStore::new(".");
        let mut tree: Self = store.read(path)?;
        if tree.tags.is_empty() && !tree.tree.is_empty() {
            tree.flatten_tree();
        }
        Ok(tree)
    }

    pub fn normalize_tag<'a>(&'a self, value: &str) -> Option<&'a str> {
        self.tags.iter().find_map(|tag| {
            if tag.id == value || tag.aliases.iter().any(|alias| alias == value) {
                Some(tag.id.as_str())
            } else {
                None
            }
        })
    }

    pub fn is_descendant_or_same(&self, tag_id: &str, domain_id: &str) -> bool {
        if domain_id == "*" || tag_id == domain_id {
            return true;
        }

        let by_id = self
            .tags
            .iter()
            .map(|tag| (tag.id.as_str(), tag))
            .collect::<BTreeMap<_, _>>();
        let mut current = by_id.get(tag_id).and_then(|tag| tag.parent.as_deref());
        let mut seen = BTreeSet::new();

        while let Some(parent) = current {
            if parent == domain_id {
                return true;
            }
            if !seen.insert(parent) {
                return false;
            }
            current = by_id.get(parent).and_then(|tag| tag.parent.as_deref());
        }

        false
    }

    pub fn matches_authorized_domains(
        &self,
        capability_tags: &[String],
        authorized_domains: &[String],
    ) -> bool {
        if authorized_domains.iter().any(|domain| domain == "*") {
            return true;
        }

        capability_tags.iter().any(|capability| {
            let normalized_capability = self.normalize_tag(capability).unwrap_or(capability);
            authorized_domains.iter().any(|domain| {
                let normalized_domain = self.normalize_tag(domain).unwrap_or(domain);
                self.is_descendant_or_same(normalized_capability, normalized_domain)
            })
        })
    }

    pub fn flatten_tree(&mut self) {
        if !self.tags.is_empty() || self.tree.is_empty() {
            return;
        }

        fn walk(node: &CapabilityTreeNode, parent: Option<&str>, tags: &mut Vec<CapabilityTag>) {
            tags.push(CapabilityTag {
                id: node.id.clone(),
                label: node.label.clone(),
                parent: parent.map(ToOwned::to_owned),
                aliases: vec![],
            });
            for child in &node.children {
                walk(child, Some(node.id.as_str()), tags);
            }
        }

        for node in &self.tree {
            walk(node, None, &mut self.tags);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedDomain {
    pub id: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedDomainTreeNode {
    pub id: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<AuthorizedDomainTreeNode>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedDomainTaxonomy {
    pub version: u64,
    #[serde(rename = "snapshotHash", skip_serializing_if = "Option::is_none")]
    pub snapshot_hash: Option<String>,
    #[serde(default)]
    pub domains: Vec<AuthorizedDomain>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tree: Vec<AuthorizedDomainTreeNode>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorizedDomainError {
    #[error("authorized domain list must not mix wildcard with concrete domains")]
    WildcardMixed,
    #[error("authorized domains must be sorted and unique")]
    DuplicateOrUnsorted,
    #[error("authorized domain is empty")]
    EmptyDomain,
    #[error("authorized domain is not canonical")]
    NonCanonicalDomain,
    #[error("authorized domain is unknown")]
    UnknownDomain,
}

impl AuthorizedDomainTaxonomy {
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, oan_storage::StorageError> {
        let store = oan_storage::JsonStore::new(".");
        let mut taxonomy: Self = store.read(path)?;
        if taxonomy.domains.is_empty() && !taxonomy.tree.is_empty() {
            taxonomy.flatten_tree();
        }
        Ok(taxonomy)
    }

    pub fn normalize_domain<'a>(&'a self, value: &str) -> Option<&'a str> {
        self.domains.iter().find_map(|domain| {
            if domain.id == value || domain.aliases.iter().any(|alias| alias == value) {
                Some(domain.id.as_str())
            } else {
                None
            }
        })
    }

    pub fn validate_authorized_domains(
        &self,
        domains: &[String],
    ) -> Result<Vec<String>, AuthorizedDomainError> {
        if domains.is_empty() {
            return Ok(Vec::new());
        }
        if domains.iter().any(|domain| domain == "*") {
            return if domains.len() == 1 {
                Ok(vec!["*".to_owned()])
            } else {
                Err(AuthorizedDomainError::WildcardMixed)
            };
        }

        let mut normalized = Vec::with_capacity(domains.len());
        for domain in domains {
            if domain.is_empty() {
                return Err(AuthorizedDomainError::EmptyDomain);
            }
            let canonical = self
                .normalize_domain(domain)
                .ok_or(AuthorizedDomainError::UnknownDomain)?;
            if canonical != domain {
                return Err(AuthorizedDomainError::NonCanonicalDomain);
            }
            if canonical.matches('.').count() > 1 {
                return Err(AuthorizedDomainError::NonCanonicalDomain);
            }
            normalized.push(canonical.to_owned());
        }

        if normalized.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(AuthorizedDomainError::DuplicateOrUnsorted);
        }

        Ok(normalized)
    }

    pub fn covers_authorized_domains(
        &self,
        requested_domains: &[String],
        granted_domains: &[String],
    ) -> bool {
        if requested_domains.is_empty() {
            return true;
        }
        if granted_domains.iter().any(|domain| domain == "*") {
            return true;
        }
        if granted_domains.is_empty() {
            return false;
        }

        requested_domains.iter().all(|requested| {
            let Some(normalized_requested) = self.normalize_domain(requested) else {
                return false;
            };
            granted_domains.iter().any(|granted| {
                self.normalize_domain(granted)
                    .is_some_and(|normalized_granted| {
                        self.is_descendant_or_same(normalized_requested, normalized_granted)
                    })
            })
        })
    }

    pub fn flatten_tree(&mut self) {
        if !self.domains.is_empty() || self.tree.is_empty() {
            return;
        }

        fn walk(
            node: &AuthorizedDomainTreeNode,
            parent: Option<&str>,
            domains: &mut Vec<AuthorizedDomain>,
        ) {
            domains.push(AuthorizedDomain {
                id: node.id.clone(),
                label: node.label.clone(),
                parent: parent.map(ToOwned::to_owned),
                aliases: vec![],
            });
            for child in &node.children {
                walk(child, Some(node.id.as_str()), domains);
            }
        }

        for node in &self.tree {
            walk(node, None, &mut self.domains);
        }
    }

    fn is_descendant_or_same(&self, domain_id: &str, granted_domain_id: &str) -> bool {
        if granted_domain_id == "*" || domain_id == granted_domain_id {
            return true;
        }

        let by_id = self
            .domains
            .iter()
            .map(|domain| (domain.id.as_str(), domain))
            .collect::<BTreeMap<_, _>>();
        let mut current = by_id
            .get(domain_id)
            .and_then(|domain| domain.parent.as_deref());
        let mut seen = BTreeSet::new();

        while let Some(parent) = current {
            if parent == granted_domain_id {
                return true;
            }
            if !seen.insert(parent) {
                return false;
            }
            current = by_id
                .get(parent)
                .and_then(|domain| domain.parent.as_deref());
        }

        false
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DidDocumentError {
    #[error("did document id is empty")]
    EmptyId,
    #[error("did document context must include https://www.w3.org/ns/did/v1")]
    MissingDidCoreContext,
    #[error("did document must include at least one verification method")]
    MissingVerificationMethod,
    #[error("did document must include at least one authentication method")]
    MissingAuthentication,
    #[error("did document must include at least one assertion method")]
    MissingAssertionMethod,
    #[error("oan metadata missing")]
    MissingOanMetadata,
    #[error("oan subject type and resource type must match for discoverable resources")]
    ResourceTypeMismatch,
    #[error("did:oan identifier does not match profile-v2 syntax")]
    InvalidDidOanIdentifier,
    #[error("did document controller is required")]
    MissingController,
    #[error("did document top-level proof is required")]
    MissingProof,
    #[error("did document proof is invalid: {0}")]
    InvalidProof(&'static str),
    #[error("external identifier list is invalid: {0}")]
    InvalidExternalIdentifier(&'static str),
    #[error("subject type and resource type combination is invalid")]
    InvalidTypeCombination,
    #[error("oan metadata controllerDid must match the top-level controller")]
    ControllerDidMismatch,
}

impl DidDocument {
    pub fn validate_mvp(&self) -> Result<(), DidDocumentError> {
        if self.id.is_empty() {
            return Err(DidDocumentError::EmptyId);
        }
        if !self
            .context
            .iter()
            .any(|value| value == "https://www.w3.org/ns/did/v1")
        {
            return Err(DidDocumentError::MissingDidCoreContext);
        }
        if self.verification_method.is_empty() {
            return Err(DidDocumentError::MissingVerificationMethod);
        }
        if self.authentication.is_empty() {
            return Err(DidDocumentError::MissingAuthentication);
        }
        if self.assertion_method.is_empty() {
            return Err(DidDocumentError::MissingAssertionMethod);
        }
        Ok(())
    }

    pub fn validate_oan_resource(&self) -> Result<(), DidDocumentError> {
        self.validate_mvp()?;
        let controller = self
            .controller
            .as_ref()
            .ok_or(DidDocumentError::MissingController)?;
        let metadata = self
            .oan_metadata
            .as_ref()
            .ok_or(DidDocumentError::MissingOanMetadata)?;
        if let Some(controller_did) = metadata.controller_did.as_deref() {
            if !controller.contains(controller_did) {
                return Err(DidDocumentError::ControllerDidMismatch);
            }
        }
        if !valid_type_combination(&metadata.subject_type, &metadata.resource_type) {
            return Err(DidDocumentError::InvalidTypeCombination);
        }
        if metadata.subject_type == SubjectType::Controller
            && metadata.resource_type == ResourceType::Controller
            && !controller.contains(&self.id)
        {
            return Err(DidDocumentError::ControllerDidMismatch);
        }
        let did = oan_did_oan::DidOan::parse(&self.id)
            .map_err(|_| DidDocumentError::InvalidDidOanIdentifier)?;
        let _ = did;
        let proof = self.proof.as_ref().ok_or(DidDocumentError::MissingProof)?;
        validate_proof(self, controller, proof)?;
        validate_external_identifiers(&metadata.external_identifiers)?;
        Ok(())
    }
}

fn valid_type_combination(subject: &SubjectType, resource: &ResourceType) -> bool {
    matches!(
        (subject, resource),
        (SubjectType::AgentInstance, ResourceType::AgentInstance)
            | (SubjectType::AgentInstance, ResourceType::AgentService)
            | (SubjectType::AgentProduct, ResourceType::AgentProduct)
            | (SubjectType::Organization, ResourceType::Organization)
            | (SubjectType::Developer, ResourceType::Developer)
            | (SubjectType::AgentService, ResourceType::AgentService)
            | (SubjectType::Skill, ResourceType::Skill)
            | (SubjectType::McpServer, ResourceType::McpServer)
            | (SubjectType::ToolApi, ResourceType::ToolApi)
            | (
                SubjectType::InfrastructureNode,
                ResourceType::InfrastructureNode
            )
            | (SubjectType::InfrastructureNode, ResourceType::RootNode)
            | (SubjectType::InfrastructureNode, ResourceType::RegistrarNode)
            | (SubjectType::InfrastructureNode, ResourceType::DiscoveryNode)
            | (SubjectType::InfrastructureNode, ResourceType::CdnNode)
            | (SubjectType::InfrastructureNode, ResourceType::VcIssuerNode)
            | (
                SubjectType::InfrastructureNode,
                ResourceType::TrustIndexerNode
            )
            | (SubjectType::RootNode, ResourceType::RootNode)
            | (SubjectType::RegistrarNode, ResourceType::RegistrarNode)
            | (SubjectType::DiscoveryNode, ResourceType::DiscoveryNode)
            | (SubjectType::CdnNode, ResourceType::CdnNode)
            | (SubjectType::VcIssuerNode, ResourceType::VcIssuerNode)
            | (
                SubjectType::TrustIndexerNode,
                ResourceType::TrustIndexerNode
            )
            | (SubjectType::Controller, ResourceType::Controller)
            | (SubjectType::Unspecified, ResourceType::Unspecified)
    )
}

fn validate_proof(
    document: &DidDocument,
    controller: &DidController,
    proof: &DataIntegrityProof,
) -> Result<(), DidDocumentError> {
    if proof.proof_purpose != "assertionMethod" {
        return Err(DidDocumentError::InvalidProof("proofPurpose"));
    }
    let verification_method = proof
        .verification_method
        .as_deref()
        .ok_or(DidDocumentError::InvalidProof("verificationMethod"))?;
    if proof.creator != verification_method {
        return Err(DidDocumentError::InvalidProof("creator"));
    }
    if !document
        .assertion_method
        .iter()
        .any(|method| method == verification_method)
    {
        return Err(DidDocumentError::InvalidProof("assertionMethod"));
    }
    let method = document
        .verification_method
        .iter()
        .find(|method| method.id == verification_method)
        .ok_or(DidDocumentError::InvalidProof(
            "verificationMethodReference",
        ))?;
    if !controller.contains(&method.controller) {
        return Err(DidDocumentError::InvalidProof("controller"));
    }
    if proof.crypto_suite.is_none() {
        return Err(DidDocumentError::InvalidProof("cryptoSuite"));
    }
    if proof.hash_algorithm.is_none() {
        return Err(DidDocumentError::InvalidProof("hashAlgorithm"));
    }
    let suite = proof.crypto_suite.as_ref().expect("checked above");
    if matches!(suite, CryptoSuite::Ed25519Sha256Legacy) {
        return Err(DidDocumentError::InvalidProof("legacyCryptoSuite"));
    }
    let hash_algorithm = suite.canonical_hash_algorithm();
    if proof.proof_type != suite.proof_type()
        || proof.hash_algorithm.as_deref() != Some(hash_algorithm)
        || method.crypto_suite.as_ref() != Some(suite)
        || method.method_type != suite.verification_method_type()
    {
        return Err(DidDocumentError::InvalidProof("algorithmMismatch"));
    }
    Ok(())
}

fn validate_external_identifiers(values: &[ExternalIdentifier]) -> Result<(), DidDocumentError> {
    if values.len() > 8 {
        return Err(DidDocumentError::InvalidExternalIdentifier("maxItems"));
    }
    let mut ids = BTreeSet::new();
    for value in values {
        if value.id.is_empty()
            || value.id.len() > 512
            || value.id.chars().any(|ch| ch.is_control())
            || value.id.starts_with("did:oan:")
        {
            return Err(DidDocumentError::InvalidExternalIdentifier("id"));
        }
        if !ids.insert(&value.id) {
            return Err(DidDocumentError::InvalidExternalIdentifier("duplicate"));
        }
        if let Some(endpoint) = &value.resolution_service_endpoint {
            if endpoint.len() > 1024 {
                return Err(DidDocumentError::InvalidExternalIdentifier(
                    "endpointLength",
                ));
            }
            let parsed = url::Url::parse(endpoint)
                .map_err(|_| DidDocumentError::InvalidExternalIdentifier("endpointUri"))?;
            if matches!(parsed.scheme(), "file" | "data" | "javascript")
                || !parsed.username().is_empty()
                || parsed.password().is_some()
            {
                return Err(DidDocumentError::InvalidExternalIdentifier(
                    "endpointSafety",
                ));
            }
        }
    }
    let serialized = serde_json::to_vec(values)
        .map_err(|_| DidDocumentError::InvalidExternalIdentifier("serialization"))?;
    if serialized.len() > 8192 {
        return Err(DidDocumentError::InvalidExternalIdentifier("maxBytes"));
    }
    Ok(())
}

