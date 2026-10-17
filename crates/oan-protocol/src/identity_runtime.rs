// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! Experimental edge context, carried in an existing signed envelope body.
//! Parsing this context does not authenticate a caller.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityMessageContext {
    pub profile: IdentityMessageProfile,
    pub sender_did: String,
    pub audience_did: String,
    pub purpose: IdentityMessagePurpose,
    pub protocol: IdentityMessageProtocol,
    pub session_id: String,
    pub message_id: String,
    pub request_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub nonce: String,
    pub payload_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityMessageProfile {
    #[serde(rename = "oan-message-v1")]
    V1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityMessagePurpose {
    Request,
    Response,
    Challenge,
    Event,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityMessageProtocol {
    Http,
    Mcp,
    A2a,
}

