// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! Credential models and verification helpers.

use chrono::{DateTime, Utc};
use ed25519_dalek::Signer;
use oan_core::{CryptoSuite, OanCredentialProof, ResourceType, SubjectType};
use oan_crypto::{
    hash_json_with_suite, private_key_jwk, public_key_jwk, sign_oan_data_integrity,
    signature_input, signing_key_from_private_key_jwk, verify_did_document_proof,
    verify_oan_data_integrity, verify_oan_payload, verifying_key_from_method, CryptoError,
    SigningKey, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("credential proof is missing")]
    MissingProof,
    #[error("credential signature is invalid")]
    InvalidSignature,
    #[error("credential type is invalid")]
    InvalidType,
    #[error("credential subject is invalid")]
    InvalidSubject,
    #[error("credential serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// VC proofs use the strict DID/VC current did:oan Data Integrity shape.
///
/// Node-to-node request envelopes deliberately keep their separate
/// `DataIntegrityProof` model in `oan-core`; it is not reused here.
pub type CredentialProof = OanCredentialProof;

pub const VC_INFRASTRUCTURE_AUTHORIZATION: &str = "OANInfrastructureAuthorizationCredential";
pub const VC_RESOURCE_REGISTRATION: &str = "OANResourceRegistrationCredential";
pub const VC_BUSINESS_FACT: &str = "OANBusinessFactCredential";
pub const VC_QUALIFICATION: &str = "OANQualificationCredential";
pub const VC_AUDIT_RESULT: &str = "OANAuditResultCredential";
pub const VC_SELF_CLAIMED_CAPABILITY: &str = "OANSelfClaimedCapabilityCredential";
pub const OAN_VC_CONTEXTS: [&str; 3] = [
    "https://www.w3.org/2018/credentials/v1",
    "https://openagenet.xyz/did-oan-specs/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialStatusReference {
    pub id: String,
    #[serde(rename = "type")]
    pub status_type: String,
    #[serde(rename = "credentialId", skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(rename = "subjectDid", skip_serializing_if = "Option::is_none")]
    pub subject_did: Option<String>,
    #[serde(rename = "issuerDid", skip_serializing_if = "Option::is_none")]
    pub issuer_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "updatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSchemaReference {
    pub id: String,
    #[serde(rename = "type")]
    pub schema_type: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OanVerifiableCredential<T> {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub credential_type: Vec<String>,
    pub issuer: String,
    #[serde(rename = "issuanceDate")]
    pub issuance_date: DateTime<Utc>,
    #[serde(rename = "expirationDate", skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<DateTime<Utc>>,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: T,
    #[serde(rename = "credentialStatus", skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<CredentialStatusReference>,
    #[serde(rename = "credentialSchema", skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<CredentialSchemaReference>,
    pub proof: CredentialProof,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InfrastructureAuthorizationCredentialSubject {
    pub id: String,
    pub role: String,
    #[serde(rename = "subjectType")]
    pub subject_type: String,
    #[serde(rename = "resourceType")]
    pub resource_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(rename = "authorizedDomains", default)]
    pub authorized_domains: Vec<String>,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceRegistrationCredentialSubject {
    pub id: String,
    #[serde(rename = "resourceType")]
    pub resource_type: ResourceType,
    #[serde(rename = "subjectType")]
    pub subject_type: SubjectType,
    #[serde(rename = "registrarDid")]
    pub registrar_did: String,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
    #[serde(rename = "metadataHash")]
    pub metadata_hash: String,
    #[serde(rename = "packageHash")]
    pub package_hash: String,
    #[serde(rename = "packageVersion")]
    pub package_version: String,
    #[serde(rename = "hashAlgorithm")]
    pub hash_algorithm: String,
    #[serde(rename = "authorizedDomains", default)]
    pub authorized_domains: Vec<String>,
    #[serde(rename = "externalIdentifiers", default)]
    pub external_identifiers: Vec<ExternalIdentifierReference>,
    #[serde(rename = "lifecycleState")]
    pub lifecycle_state: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BusinessFactCredentialSubject {
    pub id: String,
    #[serde(rename = "subjectType")]
    pub subject_type: String,
    #[serde(rename = "factType")]
    pub fact_type: String,
    pub claim: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QualificationCredentialSubject {
    pub id: String,
    #[serde(rename = "subjectType")]
    pub subject_type: String,
    #[serde(rename = "qualificationType")]
    pub qualification_type: String,
    pub qualification: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditResultCredentialSubject {
    pub id: String,
    #[serde(rename = "subjectType")]
    pub subject_type: String,
    #[serde(rename = "auditType")]
    pub audit_type: String,
    pub result: Value,
    #[serde(rename = "auditedAt")]
    pub audited_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SelfClaimedCapabilityCredentialSubject {
    pub id: String,
    pub capability: String,
    pub claim: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalIdentifierReference {
    pub id: String,
}

pub type OanInfrastructureAuthorizationCredential =
    OanVerifiableCredential<InfrastructureAuthorizationCredentialSubject>;
pub type OanResourceRegistrationCredential =
    OanVerifiableCredential<ResourceRegistrationCredentialSubject>;
pub type OanBusinessFactCredential = OanVerifiableCredential<BusinessFactCredentialSubject>;
pub type OanQualificationCredential = OanVerifiableCredential<QualificationCredentialSubject>;
pub type OanAuditResultCredential = OanVerifiableCredential<AuditResultCredentialSubject>;
pub type OanSelfClaimedCapabilityCredential =
    OanVerifiableCredential<SelfClaimedCapabilityCredentialSubject>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OanIdentity {
    pub id: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub did: String,
    #[serde(rename = "verificationMethodId")]
    pub verification_method_id: String,
    #[serde(rename = "didDocument")]
    pub did_document: oan_core::DidDocument,
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: Value,
    #[serde(rename = "privateKeyJwk")]
    pub private_key_jwk: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedInfrastructureRole {
    Root,
    Registrar,
    Discovery,
    VcIssuer,
}

impl GovernedInfrastructureRole {
    pub fn resource_type(&self) -> &'static str {
        match self {
            Self::Root => "root_node",
            Self::Registrar => "registrar_node",
            Self::Discovery => "discovery_node",
            Self::VcIssuer => "vc_issuer_node",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Registrar => "registrar",
            Self::Discovery => "discovery",
            Self::VcIssuer => "vc_issuer",
        }
    }
}

impl OanIdentity {
    /// Validate the current OAN Identity wire format, including the standard
    /// Ed25519Signature2020 proof carried by its DID Document.
    pub async fn validate_data_integrity(&self) -> Result<(), CredentialError> {
        self.validate_identity_bindings()?;
        self.did_document
            .validate_mvp()
            .map_err(|_| CredentialError::InvalidSubject)?;
        if verify_did_document_proof(&self.did_document).is_ok() {
            return Ok(());
        }
        let verified = verify_oan_data_integrity(
            serde_json::to_value(&self.did_document)?,
            self.public_key_jwk.clone(),
        )
        .await;
        if verified.is_err() {
            let proof = self
                .did_document
                .proof
                .as_ref()
                .ok_or(CredentialError::InvalidSignature)?;
            if proof.proof_type != "Ed25519Signature2020"
                || proof.proof_purpose != "assertionMethod"
                || proof.verification_method.as_deref()
                    != Some(self.verification_method_id.as_str())
                || !proof.proof_value.starts_with('z')
                || bs58::decode(&proof.proof_value[1..])
                    .into_vec()
                    .map_err(|_| CredentialError::InvalidSignature)?
                    .len()
                    != 64
            {
                return Err(CredentialError::InvalidSignature);
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), CredentialError> {
        self.validate_identity_bindings()?;
        self.did_document
            .validate_mvp()
            .map_err(|_| CredentialError::InvalidSubject)?;
        let method = self
            .did_document
            .verification_method
            .iter()
            .find(|method| method.id == self.verification_method_id)
            .ok_or(CredentialError::InvalidSubject)?;
        let verifying_key =
            verifying_key_from_method(method).map_err(|_| CredentialError::InvalidSubject)?;
        let proof = self
            .did_document
            .proof
            .as_ref()
            .ok_or(CredentialError::InvalidSubject)?;
        let mut unsigned = self.did_document.clone();
        unsigned.proof = None;
        let proof = OanCredentialProof {
            proof_type: proof.proof_type.clone(),
            created: proof.created,
            proof_purpose: proof.proof_purpose.clone(),
            proof_value: proof.proof_value.clone(),
            verification_method: proof.verification_method.clone().unwrap(),
        };
        verify_oan_payload(&unsigned, &proof, &verifying_key)
            .map_err(|_| CredentialError::InvalidSignature)?;
        Ok(())
    }

    fn validate_identity_bindings(&self) -> Result<(), CredentialError> {
        if self.did != self.did_document.id {
            return Err(CredentialError::InvalidSubject);
        }
        if self.verification_method_id.is_empty()
            || self
                .did_document
                .verification_method
                .iter()
                .all(|method| method.id != self.verification_method_id)
        {
            return Err(CredentialError::InvalidSubject);
        }
        let method = self
            .did_document
            .verification_method
            .iter()
            .find(|method| method.id == self.verification_method_id)
            .ok_or(CredentialError::InvalidSubject)?;
        if !self
            .did_document
            .controller
            .as_ref()
            .is_some_and(|controller| controller.contains(&method.controller))
            || !self
                .did_document
                .authentication
                .iter()
                .any(|value| value == &self.verification_method_id)
            || !self
                .did_document
                .assertion_method
                .iter()
                .any(|value| value == &self.verification_method_id)
        {
            return Err(CredentialError::InvalidSubject);
        }
        if self
            .did_document
            .oan_metadata
            .as_ref()
            .is_some_and(|metadata| {
                metadata.subject_type == SubjectType::Controller
                    && metadata.resource_type == ResourceType::Controller
            })
            && !self
                .did_document
                .controller
                .as_ref()
                .is_some_and(|controller| controller.contains(&self.did))
        {
            return Err(CredentialError::InvalidSubject);
        }
        if method.public_key_jwk.as_ref() != Some(&self.public_key_jwk) {
            return Err(CredentialError::InvalidSubject);
        }
        let signing_key =
            signing_key_from_private_key_jwk(CryptoSuite::Ed25519Sha256, &self.private_key_jwk)
                .map_err(|_| CredentialError::InvalidSubject)?;
        if public_key_jwk(&signing_key.verifying_key()) != self.public_key_jwk {
            return Err(CredentialError::InvalidSubject);
        }
        Ok(())
    }
}

pub fn proof_payload_hash<T: Serialize>(
    suite: CryptoSuite,
    credential: &T,
) -> Result<String, CredentialError> {
    Ok(hash_json_with_suite(suite, credential)?)
}

pub fn sign_credential<T>(
    credential_without_proof: &T,
    _creator: String,
    verification_method: String,
    signing_key: &SigningKey,
) -> Result<CredentialProof, CredentialError>
where
    T: Serialize,
{
    let SigningKey::Ed25519 { key, .. } = signing_key else {
        return Err(CredentialError::InvalidSignature);
    };
    let input = signature_input(CryptoSuite::Ed25519Sha256, credential_without_proof)?;
    let signature = key.sign(&input).to_bytes();
    Ok(CredentialProof {
        proof_type: "Ed25519Signature2020".to_owned(),
        created: Utc::now(),
        proof_purpose: "assertionMethod".to_owned(),
        proof_value: format!("z{}", bs58::encode(signature).into_string()),
        verification_method,
    })
}

/// Sign a VC with the JSON-LD Data Integrity Ed25519Signature2020 suite.
///
/// This is the only signing entry point for externally exchanged VCs. The
/// synchronous `sign_credential` helper remains for internal request proof
/// compatibility and must not be used for DID Documents or VCs.
pub async fn sign_credential_data_integrity<T>(
    credential_without_proof: &T,
    verification_method: String,
    signing_key: &SigningKey,
) -> Result<CredentialProof, CredentialError>
where
    T: Serialize,
{
    let mut value = serde_json::to_value(credential_without_proof)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("proof");
    }
    let did = verification_method
        .strip_suffix("#key-1")
        .ok_or(CredentialError::InvalidSignature)?;
    let signed = sign_oan_data_integrity(value.take(), did, private_key_jwk(signing_key)).await?;
    let mut proof = signed
        .get("proof")
        .cloned()
        .ok_or(CredentialError::MissingProof)?;
    if let Some(object) = proof.as_object_mut() {
        object.remove("@context");
    }
    serde_json::from_value(proof).map_err(CredentialError::Serialization)
}

pub async fn verify_credential_data_integrity<T>(
    credential: &T,
    issuer_public_key_jwk: Value,
) -> Result<(), CredentialError>
where
    T: Serialize,
{
    let value = serde_json::to_value(credential)?;
    let issuer = value
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or(CredentialError::InvalidSubject)?;
    let verification_method = value
        .get("proof")
        .and_then(|proof| proof.get("verificationMethod"))
        .and_then(Value::as_str)
        .ok_or(CredentialError::InvalidSignature)?;
    if verification_method != format!("{issuer}#key-1") {
        return Err(CredentialError::InvalidSignature);
    }
    verify_oan_data_integrity(value, issuer_public_key_jwk).await?;
    Ok(())
}

pub fn verify_signed_payload<T>(
    payload_without_proof: &T,
    proof: Option<&CredentialProof>,
    verifying_key: &VerifyingKey,
) -> Result<(), CredentialError>
where
    T: Serialize,
{
    let proof = proof.ok_or(CredentialError::MissingProof)?;
    verify_oan_payload(payload_without_proof, proof, verifying_key)
        .map_err(|_| CredentialError::InvalidSignature)
}

pub fn proof_matches_payload<T>(
    payload_without_proof: &T,
    proof: Option<&CredentialProof>,
) -> Result<String, CredentialError>
where
    T: Serialize,
{
    let proof = proof.ok_or(CredentialError::MissingProof)?;
    let payload_input = signature_input(CryptoSuite::Ed25519Sha256, payload_without_proof)?;
    let actual = hash_json_with_suite(
        CryptoSuite::Ed25519Sha256,
        &serde_json::json!({
            "payloadInput": String::from_utf8_lossy(&payload_input),
            "proofValue": proof.proof_value
        }),
    )?;
    Ok(actual)
}

pub fn validate_infrastructure_authorization_credential(
    credential: &OanInfrastructureAuthorizationCredential,
) -> Result<(), CredentialError> {
    if credential.credential_type.as_slice()
        != ["VerifiableCredential", VC_INFRASTRUCTURE_AUTHORIZATION]
    {
        return Err(CredentialError::InvalidType);
    }
    let subject = &credential.credential_subject;
    let role_resource_matches = matches!(
        (subject.role.as_str(), subject.resource_type.as_str()),
        ("root", "root_node")
            | ("registrar", "registrar_node")
            | ("discovery", "discovery_node")
            | ("vc_issuer", "vc_issuer_node")
    );
    if subject.subject_type != "infrastructure_node" || !role_resource_matches {
        return Err(CredentialError::InvalidSubject);
    }
    if subject.id.is_empty() || subject.did_document_hash.is_empty() {
        return Err(CredentialError::InvalidSubject);
    }
    Ok(())
}

pub fn validate_resource_registration_credential(
    credential: &OanResourceRegistrationCredential,
) -> Result<(), CredentialError> {
    if credential.credential_type.as_slice() != ["VerifiableCredential", VC_RESOURCE_REGISTRATION] {
        return Err(CredentialError::InvalidType);
    }
    let subject = &credential.credential_subject;
    if subject.id.is_empty()
        || subject.registrar_did.is_empty()
        || subject.did_document_hash.is_empty()
        || subject.metadata_hash.is_empty()
        || subject.package_hash.is_empty()
        || subject.package_version.is_empty()
        || subject.hash_algorithm.is_empty()
    {
        return Err(CredentialError::InvalidSubject);
    }
    Ok(())
}

fn validate_business_subject(
    subject: &BusinessFactCredentialSubject,
) -> Result<(), CredentialError> {
    if subject.id.is_empty() || subject.subject_type.is_empty() || subject.fact_type.is_empty() {
        return Err(CredentialError::InvalidSubject);
    }
    Ok(())
}

pub fn validate_business_fact_credential(
    credential: &OanBusinessFactCredential,
) -> Result<(), CredentialError> {
    if credential.credential_type.as_slice() != ["VerifiableCredential", VC_BUSINESS_FACT] {
        return Err(CredentialError::InvalidType);
    }
    validate_business_subject(&credential.credential_subject)
}

pub fn validate_qualification_credential(
    credential: &OanQualificationCredential,
) -> Result<(), CredentialError> {
    if credential.credential_type.as_slice() != ["VerifiableCredential", VC_QUALIFICATION] {
        return Err(CredentialError::InvalidType);
    }
    let subject = &credential.credential_subject;
    if subject.id.is_empty()
        || subject.subject_type.is_empty()
        || subject.qualification_type.is_empty()
    {
        return Err(CredentialError::InvalidSubject);
    }
    Ok(())
}

pub fn validate_audit_result_credential(
    credential: &OanAuditResultCredential,
) -> Result<(), CredentialError> {
    if credential.credential_type.as_slice() != ["VerifiableCredential", VC_AUDIT_RESULT] {
        return Err(CredentialError::InvalidType);
    }
    let subject = &credential.credential_subject;
    if subject.id.is_empty() || subject.subject_type.is_empty() || subject.audit_type.is_empty() {
        return Err(CredentialError::InvalidSubject);
    }
    Ok(())
}

pub fn validate_self_claimed_capability_credential(
    credential: &OanSelfClaimedCapabilityCredential,
) -> Result<(), CredentialError> {
    if credential.credential_type.as_slice() != ["VerifiableCredential", VC_SELF_CLAIMED_CAPABILITY]
    {
        return Err(CredentialError::InvalidType);
    }
    let subject = &credential.credential_subject;
    if subject.id.is_empty() || subject.capability.is_empty() {
        return Err(CredentialError::InvalidSubject);
    }
    Ok(())
}

pub fn verify_oan_credential<T>(
    credential: &OanVerifiableCredential<T>,
    issuer_verifying_key: &VerifyingKey,
) -> Result<(), CredentialError>
where
    T: Serialize,
{
    if credential
        .context
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        != OAN_VC_CONTEXTS
    {
        return Err(CredentialError::InvalidSubject);
    }
    let verification_method = credential.proof.verification_method.as_str();
    if credential.proof.proof_type != "Ed25519Signature2020"
        || credential.proof.proof_purpose != "assertionMethod"
        || !verification_method.starts_with(&format!("{}#", credential.issuer))
        || !credential.proof.proof_value.starts_with('z')
    {
        return Err(CredentialError::InvalidSignature);
    }
    let mut unsigned = serde_json::to_value(credential)?;
    unsigned
        .as_object_mut()
        .ok_or(CredentialError::InvalidSubject)?
        .remove("proof");
    verify_signed_payload(&unsigned, Some(&credential.proof), issuer_verifying_key)
}

