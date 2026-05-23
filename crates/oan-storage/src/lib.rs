// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! Storage helpers for local OpenAgenet nodes.

use serde::{de::DeserializeOwned, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("sqlite error: {0}")]
    Sqlite(#[from] sqlx::Error),
    #[error("database url must use sqlite: scheme")]
    UnsupportedDatabaseUrl,
    #[error("database path is empty")]
    EmptyDatabasePath,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqliteDatabaseConfig {
    url: String,
    path: PathBuf,
}

impl SqliteDatabaseConfig {
    pub fn parse(url: impl Into<String>) -> Result<Self, StorageError> {
        let url = url.into();
        let raw_path = url
            .strip_prefix("sqlite://")
            .or_else(|| url.strip_prefix("sqlite:"))
            .ok_or(StorageError::UnsupportedDatabaseUrl)?;
        if raw_path.is_empty() {
            return Err(StorageError::EmptyDatabasePath);
        }

        Ok(Self {
            path: PathBuf::from(raw_path),
            url,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Clone, Debug)]
pub struct SqliteJsonStore {
    pool: sqlx::SqlitePool,
}

impl SqliteJsonStore {
    pub async fn connect(url: &str) -> Result<Self, StorageError> {
        let config = SqliteDatabaseConfig::parse(url)?;
        if let Some(parent) = config.path().parent() {
            fs::create_dir_all(parent)?;
        }
        let options =
            sqlx::sqlite::SqliteConnectOptions::from_str(config.url())?.create_if_missing(true);
        let pool = sqlx::SqlitePool::connect_with(options).await?;
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS json_records (
                namespace TEXT NOT NULL,
                record_key TEXT NOT NULL,
                value_json TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(namespace, record_key)
            )
            "#,
        )
        .execute(&pool)
        .await?;
        Ok(Self { pool })
    }

    pub async fn upsert_json<T: Serialize>(
        &self,
        namespace: &str,
        key: &str,
        value: &T,
    ) -> Result<(), StorageError> {
        let value_json = serde_json::to_string(value)?;
        sqlx::query(
            r#"
            INSERT INTO json_records(namespace, record_key, value_json)
            VALUES (?, ?, ?)
            ON CONFLICT(namespace, record_key)
            DO UPDATE SET value_json = excluded.value_json, updated_at = CURRENT_TIMESTAMP
            "#,
        )
        .bind(namespace)
        .bind(key)
        .bind(value_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn read_namespace<T: DeserializeOwned>(
        &self,
        namespace: &str,
    ) -> Result<Vec<T>, StorageError> {
        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT value_json FROM json_records WHERE namespace = ? ORDER BY updated_at, record_key",
        )
        .bind(namespace)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|(value_json,)| serde_json::from_str(&value_json).map_err(StorageError::from))
            .collect()
    }

    pub async fn read_json<T: DeserializeOwned>(
        &self,
        namespace: &str,
        key: &str,
    ) -> Result<Option<T>, StorageError> {
        let row = sqlx::query_as::<_, (String,)>(
            "SELECT value_json FROM json_records WHERE namespace = ? AND record_key = ?",
        )
        .bind(namespace)
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(value_json,)| serde_json::from_str(&value_json).map_err(StorageError::from))
            .transpose()
    }

    pub async fn delete_json(&self, namespace: &str, key: &str) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM json_records WHERE namespace = ? AND record_key = ?")
            .bind(namespace)
            .bind(key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn count_namespace(&self, namespace: &str) -> Result<i64, StorageError> {
        let (count,) =
            sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM json_records WHERE namespace = ?")
                .bind(namespace)
                .fetch_one(&self.pool)
                .await?;
        Ok(count)
    }

    pub async fn delete_namespace(&self, namespace: &str) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM json_records WHERE namespace = ?")
            .bind(namespace)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonStore {
    root: PathBuf,
}

impl JsonStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn resolve(&self, path: impl AsRef<Path>) -> PathBuf {
        self.root.join(path)
    }

    pub fn read<T: DeserializeOwned>(&self, path: impl AsRef<Path>) -> Result<T, StorageError> {
        let bytes = fs::read(self.resolve(path))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn write<T: Serialize>(
        &self,
        path: impl AsRef<Path>,
        value: &T,
    ) -> Result<(), StorageError> {
        let path = self.resolve(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(value)?;
        fs::write(path, [bytes, b"\n".to_vec()].concat())?;
        Ok(())
    }

    pub fn exists(&self, path: impl AsRef<Path>) -> bool {
        self.resolve(path).exists()
    }
}

pub fn did_to_file_name(did: &str) -> String {
    format!("{}.json", did.replace(':', "_"))
}

pub fn storage_safe_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalCredentialStore {
    store: JsonStore,
}

impl LocalCredentialStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            store: JsonStore::new(root),
        }
    }

    pub fn root(&self) -> &Path {
        self.store.root()
    }

    pub fn write_node_authorization<T: Serialize>(
        &self,
        credential: &T,
    ) -> Result<(), StorageError> {
        self.write_credential("node-authorization", "root", "self", "latest", credential)?;
        self.store
            .write("credentials/node-authorization.json", credential)
    }

    pub fn read_node_authorization<T: DeserializeOwned>(&self) -> Result<T, StorageError> {
        self.store.read("credentials/node-authorization.json")
    }

    pub fn write_agent_registration<T: Serialize>(
        &self,
        agent_did: &str,
        credential: &T,
    ) -> Result<(), StorageError> {
        self.write_credential(
            "agent-registration",
            "registrar",
            agent_did,
            "latest",
            credential,
        )?;
        self.store.write(
            Path::new("credentials")
                .join("agent-registrations")
                .join(did_to_file_name(agent_did)),
            credential,
        )
    }

    pub fn read_agent_registration<T: DeserializeOwned>(
        &self,
        agent_did: &str,
    ) -> Result<T, StorageError> {
        self.store.read(
            Path::new("credentials")
                .join("agent-registrations")
                .join(did_to_file_name(agent_did)),
        )
    }

    pub fn write_credential<T: Serialize>(
        &self,
        dimension: &str,
        issuer: &str,
        subject: &str,
        credential_id: &str,
        credential: &T,
    ) -> Result<(), StorageError> {
        self.store.write(
            Self::credential_path(dimension, issuer, subject, credential_id),
            credential,
        )
    }

    pub fn read_credential<T: DeserializeOwned>(
        &self,
        dimension: &str,
        issuer: &str,
        subject: &str,
        credential_id: &str,
    ) -> Result<T, StorageError> {
        self.store.read(Self::credential_path(
            dimension,
            issuer,
            subject,
            credential_id,
        ))
    }

    pub fn credential_path(
        dimension: &str,
        issuer: &str,
        subject: &str,
        credential_id: &str,
    ) -> PathBuf {
        Path::new("credentials")
            .join("by-dimension")
            .join(storage_safe_name(dimension))
            .join(storage_safe_name(issuer))
            .join(storage_safe_name(subject))
            .join(format!("{}.json", storage_safe_name(credential_id)))
    }
}

