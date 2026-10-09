// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! Storage helpers for local OpenAgenet nodes.

use futures_util::TryStreamExt;
use serde::{de::DeserializeOwned, Serialize};
use sqlx::{Executor, Pool, Postgres, QueryBuilder, Sqlite};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("sql error: {0}")]
    Sql(#[from] sqlx::Error),
    #[error("unsupported database url scheme")]
    UnsupportedDatabaseUrl,
    #[error("database path is empty")]
    EmptyDatabasePath,
    #[error("page limit {requested} exceeds maximum {maximum}")]
    PageLimitExceeded { requested: u32, maximum: u32 },
    #[error("record payload is {actual} bytes, maximum is {maximum}")]
    RecordTooLarge { actual: usize, maximum: usize },
    #[error("page payload is {actual} bytes, maximum is {maximum}")]
    PageTooLarge { actual: usize, maximum: usize },
    #[error("json directory contains {actual} entries, maximum scan size is {maximum}")]
    PageScanTooLarge { actual: usize, maximum: usize },
    #[error("invalid query limits: {reason}")]
    InvalidQueryLimits { reason: &'static str },
}

pub const DEFAULT_PAGE_SIZE: u32 = 100;
pub const MAX_PAGE_SIZE: u32 = 500;
pub const DEFAULT_MAX_RECORD_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_PAGE_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_MAX_JSON_SCAN_ENTRIES: usize = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryLimits {
    pub default_page_size: u32,
    pub max_page_size: u32,
    pub max_record_bytes: usize,
    pub max_page_bytes: usize,
    pub max_json_scan_entries: usize,
}

impl Default for QueryLimits {
    fn default() -> Self {
        Self {
            default_page_size: DEFAULT_PAGE_SIZE,
            max_page_size: MAX_PAGE_SIZE,
            max_record_bytes: DEFAULT_MAX_RECORD_BYTES,
            max_page_bytes: DEFAULT_MAX_PAGE_BYTES,
            max_json_scan_entries: DEFAULT_MAX_JSON_SCAN_ENTRIES,
        }
    }
}

impl QueryLimits {
    fn validate(self) -> Result<(), StorageError> {
        if self.default_page_size == 0 {
            return Err(StorageError::InvalidQueryLimits {
                reason: "default page size must be greater than zero",
            });
        }
        if self.max_page_size == 0 {
            return Err(StorageError::InvalidQueryLimits {
                reason: "maximum page size must be greater than zero",
            });
        }
        if self.default_page_size > self.max_page_size {
            return Err(StorageError::InvalidQueryLimits {
                reason: "default page size must not exceed maximum page size",
            });
        }
        if self.max_record_bytes == 0 {
            return Err(StorageError::InvalidQueryLimits {
                reason: "maximum record bytes must be greater than zero",
            });
        }
        if self.max_page_bytes == 0 {
            return Err(StorageError::InvalidQueryLimits {
                reason: "maximum page bytes must be greater than zero",
            });
        }
        if self.max_json_scan_entries == 0 {
            return Err(StorageError::InvalidQueryLimits {
                reason: "maximum json scan entries must be greater than zero",
            });
        }
        Ok(())
    }

    pub fn normalize_limit(self, requested: Option<u32>) -> Result<u32, StorageError> {
        self.validate()?;
        let limit = requested.unwrap_or(self.default_page_size);
        if limit == 0 {
            return Ok(self.default_page_size);
        }
        if limit > self.max_page_size {
            return Err(StorageError::PageLimitExceeded {
                requested: limit,
                maximum: self.max_page_size,
            });
        }
        Ok(limit)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespacePageCursor {
    pub updated_at: String,
    pub record_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespacePage<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<NamespacePageCursor>,
    pub has_more: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonFilePageCursor {
    pub entry_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonFilePage<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<JsonFilePageCursor>,
    pub has_more: bool,
}

fn append_namespace_item<T: DeserializeOwned>(
    items: &mut Vec<T>,
    total_bytes: &mut usize,
    next_cursor: &mut Option<NamespacePageCursor>,
    row: (String, String, String),
    limits: QueryLimits,
) -> Result<(), StorageError> {
    let (updated_at, record_key, value_json) = row;
    let bytes = value_json.len();
    if bytes > limits.max_record_bytes {
        return Err(StorageError::RecordTooLarge {
            actual: bytes,
            maximum: limits.max_record_bytes,
        });
    }
    *total_bytes = total_bytes.saturating_add(bytes);
    if *total_bytes > limits.max_page_bytes {
        return Err(StorageError::PageTooLarge {
            actual: *total_bytes,
            maximum: limits.max_page_bytes,
        });
    }
    items.push(serde_json::from_str(&value_json)?);
    *next_cursor = Some(NamespacePageCursor {
        updated_at,
        record_key,
    });
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabaseBackend {
    Sqlite,
    Postgres,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatabaseConfig {
    backend: DatabaseBackend,
    url: String,
    path: Option<PathBuf>,
}

impl DatabaseConfig {
    pub fn parse(url: impl Into<String>) -> Result<Self, StorageError> {
        let url = url.into();
        if let Some(raw_path) = url
            .strip_prefix("sqlite://")
            .or_else(|| url.strip_prefix("sqlite:"))
        {
            if raw_path.is_empty() {
                return Err(StorageError::EmptyDatabasePath);
            }
            return Ok(Self {
                backend: DatabaseBackend::Sqlite,
                path: Some(PathBuf::from(raw_path)),
                url,
            });
        }
        if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            return Ok(Self {
                backend: DatabaseBackend::Postgres,
                path: None,
                url,
            });
        }
        Err(StorageError::UnsupportedDatabaseUrl)
    }

    pub fn backend(&self) -> DatabaseBackend {
        self.backend
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

#[derive(Clone, Debug)]
pub struct SqliteJsonStore {
    pool: Pool<Sqlite>,
}

#[derive(Clone, Debug)]
pub struct PostgresJsonStore {
    pool: Pool<Postgres>,
}

#[derive(Clone, Debug)]
pub enum DatabaseStore {
    Sqlite(SqliteJsonStore),
    Postgres(PostgresJsonStore),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeasedJob<T> {
    pub job_key: String,
    pub payload: T,
    pub attempt_count: i64,
}

impl SqliteJsonStore {
    pub async fn connect(url: &str) -> Result<Self, StorageError> {
        let config = DatabaseConfig::parse(url)?;
        if config.backend() != DatabaseBackend::Sqlite {
            return Err(StorageError::UnsupportedDatabaseUrl);
        }
        let path = config.path().ok_or(StorageError::EmptyDatabasePath)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let options = sqlx::sqlite::SqliteConnectOptions::from_str(config.url())?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(30));
        let max_connections = configured_pool_max_connections("OAN_SQLITE_MAX_CONNECTIONS", 32);
        let acquire_timeout_seconds =
            configured_pool_timeout_seconds("OAN_SQLITE_ACQUIRE_TIMEOUT_SECONDS", 30);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(acquire_timeout_seconds))
            .connect_with(options)
            .await?;
        ensure_json_records_sqlite(&pool).await?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &Pool<Sqlite> {
        &self.pool
    }

    pub async fn execute_batch(&self, sql: &str) -> Result<(), StorageError> {
        self.pool.execute(sql).await?;
        Ok(())
    }

    pub async fn ensure_leased_job_table(&self, table: &str) -> Result<(), StorageError> {
        let table = validated_identifier(table)?;
        let sql = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {table} (
                job_key TEXT NOT NULL PRIMARY KEY,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                lease_owner TEXT,
                lease_expires_at TEXT,
                next_attempt_at TEXT NOT NULL,
                last_error TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            "#
        );
        self.pool.execute(sql.as_str()).await?;
        Ok(())
    }

    pub async fn enqueue_leased_job<T: Serialize>(
        &self,
        table: &str,
        job_key: &str,
        value: &T,
        next_attempt_at: &str,
    ) -> Result<(), StorageError> {
        let table = validated_identifier(table)?;
        let value_json = serde_json::to_string(value)?;
        let sql = format!(
            r#"
            INSERT INTO {table}(job_key, payload_json, status, attempt_count, lease_owner, lease_expires_at, next_attempt_at, last_error)
            VALUES (?, ?, 'ready', 0, NULL, NULL, ?, NULL)
            ON CONFLICT(job_key)
            DO UPDATE SET
                payload_json = excluded.payload_json,
                status = 'ready',
                lease_owner = NULL,
                lease_expires_at = NULL,
                next_attempt_at = excluded.next_attempt_at,
                last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            "#
        );
        sqlx::query(sql.as_str())
            .bind(job_key)
            .bind(value_json)
            .bind(next_attempt_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn lease_ready_jobs<T: DeserializeOwned>(
        &self,
        table: &str,
        worker_id: &str,
        limit: i64,
        now: &str,
        lease_expires_at: &str,
    ) -> Result<Vec<LeasedJob<T>>, StorageError> {
        let table = validated_identifier(table)?;
        let select_sql = format!(
            r#"
            SELECT job_key, payload_json, attempt_count
            FROM {table}
            WHERE
                (
                    status = 'ready'
                    OR (status = 'retry-wait' AND next_attempt_at <= ?)
                    OR (status = 'leased' AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?)
                )
            ORDER BY next_attempt_at, created_at, job_key
            LIMIT ?
            "#
        );
        let update_sql = format!(
            r#"
            UPDATE {table}
            SET
                status = 'leased',
                lease_owner = ?,
                lease_expires_at = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE
                job_key = ?
                AND (
                    status = 'ready'
                    OR (status = 'retry-wait' AND next_attempt_at <= ?)
                    OR (status = 'leased' AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?)
                )
            "#
        );

        let mut tx = self.pool.begin().await?;
        let selected = sqlx::query_as::<_, (String, String, i64)>(select_sql.as_str())
            .bind(now)
            .bind(now)
            .bind(limit)
            .fetch_all(&mut *tx)
            .await?;
        let mut leased = Vec::new();
        for (job_key, payload_json, attempt_count) in selected {
            let result = sqlx::query(update_sql.as_str())
                .bind(worker_id)
                .bind(lease_expires_at)
                .bind(&job_key)
                .bind(now)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            if result.rows_affected() == 0 {
                continue;
            }
            leased.push(LeasedJob {
                job_key,
                payload: serde_json::from_str(&payload_json)?,
                attempt_count,
            });
        }
        tx.commit().await?;
        Ok(leased)
    }

    pub async fn mark_leased_job_succeeded(
        &self,
        table: &str,
        job_key: &str,
    ) -> Result<(), StorageError> {
        let table = validated_identifier(table)?;
        let sql = format!(
            r#"
            UPDATE {table}
            SET
                status = 'succeeded',
                lease_owner = NULL,
                lease_expires_at = NULL,
                last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE job_key = ?
            "#
        );
        sqlx::query(sql.as_str())
            .bind(job_key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn mark_leased_jobs_succeeded(
        &self,
        table: &str,
        job_keys: &[String],
    ) -> Result<u64, StorageError> {
        if job_keys.is_empty() {
            return Ok(0);
        }
        let table = validated_identifier(table)?;
        let mut affected = 0u64;
        let mut tx = self.pool.begin().await?;
        for chunk in job_keys.chunks(500) {
            let mut builder = QueryBuilder::<Sqlite>::new(format!(
                r#"
                UPDATE {table}
                SET
                    status = 'succeeded',
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    last_error = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE job_key IN (
                "#
            ));
            let mut separated = builder.separated(", ");
            for job_key in chunk {
                separated.push_bind(job_key);
            }
            separated.push_unseparated(")");
            affected += builder.build().execute(&mut *tx).await?.rows_affected();
        }
        tx.commit().await?;
        Ok(affected)
    }

    pub async fn mark_leased_job_retry(
        &self,
        table: &str,
        job_key: &str,
        next_attempt_at: &str,
        last_error: Option<&str>,
    ) -> Result<(), StorageError> {
        let table = validated_identifier(table)?;
        let sql = format!(
            r#"
            UPDATE {table}
            SET
                status = 'retry-wait',
                attempt_count = attempt_count + 1,
                lease_owner = NULL,
                lease_expires_at = NULL,
                next_attempt_at = ?,
                last_error = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE job_key = ?
            "#
        );
        sqlx::query(sql.as_str())
            .bind(next_attempt_at)
            .bind(last_error)
            .bind(job_key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn mark_leased_jobs_retry(
        &self,
        table: &str,
        jobs: &[(String, String)],
        next_attempt_at: &str,
    ) -> Result<u64, StorageError> {
        if jobs.is_empty() {
            return Ok(0);
        }
        let table = validated_identifier(table)?;
        let mut affected = 0u64;
        let mut tx = self.pool.begin().await?;
        for (job_key, last_error) in jobs {
            let sql = format!(
                r#"
                UPDATE {table}
                SET
                    status = 'retry-wait',
                    attempt_count = attempt_count + 1,
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    next_attempt_at = ?,
                    last_error = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE job_key = ?
                "#
            );
            affected += sqlx::query(sql.as_str())
                .bind(next_attempt_at)
                .bind(last_error)
                .bind(job_key)
                .execute(&mut *tx)
                .await?
                .rows_affected();
        }
        tx.commit().await?;
        Ok(affected)
    }

    pub async fn read_active_leased_jobs<T: DeserializeOwned>(
        &self,
        table: &str,
    ) -> Result<Vec<T>, StorageError> {
        let table = validated_identifier(table)?;
        let sql = format!(
            r#"
            SELECT payload_json
            FROM {table}
            WHERE status IN ('ready', 'leased', 'retry-wait')
            ORDER BY updated_at, job_key
            "#
        );
        let rows = sqlx::query_as::<_, (String,)>(sql.as_str())
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|(value_json,)| serde_json::from_str(&value_json).map_err(StorageError::from))
            .collect()
    }

    pub async fn read_ready_leased_jobs<T: DeserializeOwned>(
        &self,
        table: &str,
        now: &str,
    ) -> Result<Vec<T>, StorageError> {
        let table = validated_identifier(table)?;
        let sql = format!(
            r#"
            SELECT payload_json
            FROM {table}
            WHERE
                status = 'ready'
                OR (status = 'retry-wait' AND next_attempt_at <= ?)
                OR (status = 'leased' AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?)
            ORDER BY next_attempt_at, created_at, job_key
            "#
        );
        let rows = sqlx::query_as::<_, (String,)>(sql.as_str())
            .bind(now)
            .bind(now)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|(value_json,)| serde_json::from_str(&value_json).map_err(StorageError::from))
            .collect()
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

    pub async fn read_namespace_page<T: DeserializeOwned>(
        &self,
        namespace: &str,
        cursor: Option<&NamespacePageCursor>,
        requested_limit: Option<u32>,
        limits: QueryLimits,
    ) -> Result<NamespacePage<T>, StorageError> {
        let limit = limits.normalize_limit(requested_limit)?;
        let sql = if cursor.is_some() {
            r#"
            SELECT updated_at, record_key, value_json
            FROM json_records
            WHERE namespace = ?
              AND (updated_at > ? OR (updated_at = ? AND record_key > ?))
            ORDER BY updated_at, record_key
            LIMIT ?
            "#
        } else {
            r#"
            SELECT updated_at, record_key, value_json
            FROM json_records
            WHERE namespace = ?
            ORDER BY updated_at, record_key
            LIMIT ?
            "#
        };
        let mut query = sqlx::query_as::<_, (String, String, String)>(sql).bind(namespace);
        if let Some(cursor) = cursor {
            query = query
                .bind(&cursor.updated_at)
                .bind(&cursor.updated_at)
                .bind(&cursor.record_key);
        }
        let mut stream = query.bind(i64::from(limit)).fetch(&self.pool);
        let mut items = Vec::with_capacity(limit as usize);
        let mut total_bytes = 0usize;
        let mut next_cursor = None;
        while let Some(row) = stream.try_next().await? {
            append_namespace_item(&mut items, &mut total_bytes, &mut next_cursor, row, limits)?;
        }
        let has_more = if let Some(cursor) = next_cursor.as_ref() {
            let exists = sqlx::query_scalar::<_, i64>(
                r#"
                SELECT EXISTS(
                    SELECT 1
                    FROM json_records
                    WHERE namespace = ?
                      AND (updated_at > ? OR (updated_at = ? AND record_key > ?))
                )
                "#,
            )
            .bind(namespace)
            .bind(&cursor.updated_at)
            .bind(&cursor.updated_at)
            .bind(&cursor.record_key)
            .fetch_one(&self.pool)
            .await?;
            exists != 0
        } else {
            false
        };
        Ok(NamespacePage {
            items,
            next_cursor: if has_more { next_cursor } else { None },
            has_more,
        })
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

impl PostgresJsonStore {
    pub async fn connect(url: &str) -> Result<Self, StorageError> {
        let config = DatabaseConfig::parse(url)?;
        if config.backend() != DatabaseBackend::Postgres {
            return Err(StorageError::UnsupportedDatabaseUrl);
        }
        let max_connections = configured_pool_max_connections("OAN_POSTGRES_MAX_CONNECTIONS", 8);
        let acquire_timeout_seconds =
            configured_pool_timeout_seconds("OAN_POSTGRES_ACQUIRE_TIMEOUT_SECONDS", 30);
        let pool = sqlx::postgres::PgPoolOptions::new()
            .min_connections(0)
            .max_connections(max_connections)
            .idle_timeout(Some(Duration::from_secs(30)))
            .max_lifetime(Some(Duration::from_secs(300)))
            .acquire_timeout(Duration::from_secs(acquire_timeout_seconds))
            .connect(config.url())
            .await?;
        ensure_json_records_postgres(&pool).await?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &Pool<Postgres> {
        &self.pool
    }

    pub async fn execute_batch(&self, sql: &str) -> Result<(), StorageError> {
        self.pool.execute(sql).await?;
        Ok(())
    }

    pub async fn ensure_leased_job_table(&self, table: &str) -> Result<(), StorageError> {
        let table = validated_identifier(table)?;
        let sql = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {table} (
                job_key TEXT NOT NULL PRIMARY KEY,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL,
                attempt_count BIGINT NOT NULL DEFAULT 0,
                lease_owner TEXT,
                lease_expires_at TIMESTAMPTZ,
                next_attempt_at TIMESTAMPTZ NOT NULL,
                last_error TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_{table}_status_schedule
            ON {table}(status, next_attempt_at, lease_expires_at, job_key);
            CREATE INDEX IF NOT EXISTS idx_{table}_active_schedule
            ON {table}(next_attempt_at, lease_expires_at, created_at, job_key)
            WHERE status IN ('ready', 'leased', 'retry-wait');
            CREATE INDEX IF NOT EXISTS idx_{table}_ready_claim
            ON {table}(next_attempt_at, created_at, job_key)
            WHERE status = 'ready';
            CREATE INDEX IF NOT EXISTS idx_{table}_retry_claim
            ON {table}(next_attempt_at, created_at, job_key)
            WHERE status = 'retry-wait';
            CREATE INDEX IF NOT EXISTS idx_{table}_leased_reclaim
            ON {table}(lease_expires_at, created_at, job_key)
            WHERE status = 'leased';
            CREATE INDEX IF NOT EXISTS idx_{table}_status_updated
            ON {table}(status, updated_at, job_key);
            "#
        );
        self.pool.execute(sql.as_str()).await?;
        Ok(())
    }

    pub async fn enqueue_leased_job<T: Serialize>(
        &self,
        table: &str,
        job_key: &str,
        value: &T,
        next_attempt_at: &str,
    ) -> Result<(), StorageError> {
        let table = validated_identifier(table)?;
        let value_json = serde_json::to_string(value)?;
        let sql = format!(
            r#"
            INSERT INTO {table}(job_key, payload_json, status, attempt_count, lease_owner, lease_expires_at, next_attempt_at, last_error)
            VALUES ($1, $2, 'ready', 0, NULL, NULL, $3::timestamptz, NULL)
            ON CONFLICT(job_key)
            DO UPDATE SET
                payload_json = excluded.payload_json,
                status = 'ready',
                lease_owner = NULL,
                lease_expires_at = NULL,
                next_attempt_at = excluded.next_attempt_at,
                last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            "#
        );
        sqlx::query(sql.as_str())
            .bind(job_key)
            .bind(value_json)
            .bind(next_attempt_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn lease_ready_jobs<T: DeserializeOwned>(
        &self,
        table: &str,
        worker_id: &str,
        limit: i64,
        now: &str,
        lease_expires_at: &str,
    ) -> Result<Vec<LeasedJob<T>>, StorageError> {
        let table = validated_identifier(table)?;
        let lease_sql = format!(
            r#"
            WITH candidates AS (
                SELECT job_key
                FROM {table}
                WHERE
                    (
                        status = 'ready'
                        OR (status = 'retry-wait' AND next_attempt_at <= $1::timestamptz)
                        OR (status = 'leased' AND lease_expires_at IS NOT NULL AND lease_expires_at <= $1::timestamptz)
                    )
                ORDER BY next_attempt_at, created_at, job_key
                LIMIT $2
                FOR UPDATE SKIP LOCKED
            )
            UPDATE {table} AS jobs
            SET
                status = 'leased',
                lease_owner = $3,
                lease_expires_at = $4::timestamptz,
                updated_at = CURRENT_TIMESTAMP
            FROM candidates
            WHERE jobs.job_key = candidates.job_key
            RETURNING jobs.job_key, jobs.payload_json, jobs.attempt_count
            "#
        );
        let leased_rows = sqlx::query_as::<_, (String, String, i64)>(lease_sql.as_str())
            .bind(now)
            .bind(limit)
            .bind(worker_id)
            .bind(lease_expires_at)
            .fetch_all(&self.pool)
            .await?;
        leased_rows
            .into_iter()
            .map(|(job_key, payload_json, attempt_count)| {
                Ok(LeasedJob {
                    job_key,
                    payload: serde_json::from_str(&payload_json)?,
                    attempt_count,
                })
            })
            .collect()
    }

    pub async fn mark_leased_job_succeeded(
        &self,
        table: &str,
        job_key: &str,
    ) -> Result<(), StorageError> {
        let table = validated_identifier(table)?;
        let sql = format!(
            r#"
            UPDATE {table}
            SET
                status = 'succeeded',
                lease_owner = NULL,
                lease_expires_at = NULL,
                last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE job_key = $1
            "#
        );
        sqlx::query(sql.as_str())
            .bind(job_key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn mark_leased_jobs_succeeded(
        &self,
        table: &str,
        job_keys: &[String],
    ) -> Result<u64, StorageError> {
        if job_keys.is_empty() {
            return Ok(0);
        }
        let table = validated_identifier(table)?;
        let sql = format!(
            r#"
            UPDATE {table}
            SET
                status = 'succeeded',
                lease_owner = NULL,
                lease_expires_at = NULL,
                last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE job_key = ANY($1)
            "#
        );
        let result = sqlx::query(sql.as_str())
            .bind(job_keys)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    pub async fn mark_leased_job_retry(
        &self,
        table: &str,
        job_key: &str,
        next_attempt_at: &str,
        last_error: Option<&str>,
    ) -> Result<(), StorageError> {
        let table = validated_identifier(table)?;
        let sql = format!(
            r#"
            UPDATE {table}
            SET
                status = 'retry-wait',
                attempt_count = attempt_count + 1,
                lease_owner = NULL,
                lease_expires_at = NULL,
                next_attempt_at = $1::timestamptz,
                last_error = $2,
                updated_at = CURRENT_TIMESTAMP
            WHERE job_key = $3
            "#
        );
        sqlx::query(sql.as_str())
            .bind(next_attempt_at)
            .bind(last_error)
            .bind(job_key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn mark_leased_jobs_retry(
        &self,
        table: &str,
        jobs: &[(String, String)],
        next_attempt_at: &str,
    ) -> Result<u64, StorageError> {
        if jobs.is_empty() {
            return Ok(0);
        }
        let table = validated_identifier(table)?;
        let sql = format!(
            r#"
            WITH retry_jobs(job_key, last_error) AS (
                SELECT *
                FROM UNNEST($1::text[], $2::text[])
            )
            UPDATE {table} AS jobs
            SET
                status = 'retry-wait',
                attempt_count = jobs.attempt_count + 1,
                lease_owner = NULL,
                lease_expires_at = NULL,
                next_attempt_at = $3::timestamptz,
                last_error = retry_jobs.last_error,
                updated_at = CURRENT_TIMESTAMP
            FROM retry_jobs
            WHERE jobs.job_key = retry_jobs.job_key
            "#
        );
        let mut affected = 0u64;
        for chunk in jobs.chunks(500) {
            let job_keys = chunk
                .iter()
                .map(|(job_key, _)| job_key.as_str())
                .collect::<Vec<_>>();
            let last_errors = chunk
                .iter()
                .map(|(_, last_error)| last_error.as_str())
                .collect::<Vec<_>>();
            let result = sqlx::query(sql.as_str())
                .bind(job_keys)
                .bind(last_errors)
                .bind(next_attempt_at)
                .execute(&self.pool)
                .await?;
            affected += result.rows_affected();
        }
        Ok(affected)
    }

    pub async fn read_active_leased_jobs<T: DeserializeOwned>(
        &self,
        table: &str,
    ) -> Result<Vec<T>, StorageError> {
        let table = validated_identifier(table)?;
        let sql = format!(
            r#"
            SELECT payload_json
            FROM {table}
            WHERE status IN ('ready', 'leased', 'retry-wait')
            ORDER BY updated_at, job_key
            "#
        );
        let rows = sqlx::query_as::<_, (String,)>(sql.as_str())
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|(value_json,)| serde_json::from_str(&value_json).map_err(StorageError::from))
            .collect()
    }

    pub async fn read_ready_leased_jobs<T: DeserializeOwned>(
        &self,
        table: &str,
        now: &str,
    ) -> Result<Vec<T>, StorageError> {
        let table = validated_identifier(table)?;
        let sql = format!(
            r#"
            SELECT payload_json
            FROM {table}
            WHERE
                status = 'ready'
                OR (status = 'retry-wait' AND next_attempt_at <= $1::timestamptz)
                OR (status = 'leased' AND lease_expires_at IS NOT NULL AND lease_expires_at <= $1::timestamptz)
            ORDER BY next_attempt_at, created_at, job_key
            "#
        );
        let rows = sqlx::query_as::<_, (String,)>(sql.as_str())
            .bind(now)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|(value_json,)| serde_json::from_str(&value_json).map_err(StorageError::from))
            .collect()
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
            VALUES ($1, $2, $3)
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
            "SELECT value_json FROM json_records WHERE namespace = $1 ORDER BY updated_at, record_key",
        )
        .bind(namespace)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|(value_json,)| serde_json::from_str(&value_json).map_err(StorageError::from))
            .collect()
    }

    pub async fn read_namespace_page<T: DeserializeOwned>(
        &self,
        namespace: &str,
        cursor: Option<&NamespacePageCursor>,
        requested_limit: Option<u32>,
        limits: QueryLimits,
    ) -> Result<NamespacePage<T>, StorageError> {
        let limit = limits.normalize_limit(requested_limit)?;
        let sql = if cursor.is_some() {
            r#"
            SELECT updated_at::text, record_key, value_json
            FROM json_records
            WHERE namespace = $1
              AND (updated_at > $2::timestamptz
                   OR (updated_at = $2::timestamptz AND record_key > $3))
            ORDER BY updated_at, record_key
            LIMIT $4::bigint
            "#
        } else {
            r#"
            SELECT updated_at::text, record_key, value_json
            FROM json_records
            WHERE namespace = $1
            ORDER BY updated_at, record_key
            LIMIT $2::bigint
            "#
        };
        let mut query = sqlx::query_as::<_, (String, String, String)>(sql).bind(namespace);
        if let Some(cursor) = cursor {
            query = query
                .bind(&cursor.updated_at)
                .bind(&cursor.record_key);
        }
        let mut stream = query.bind(i64::from(limit)).fetch(&self.pool);
        let mut items = Vec::with_capacity(limit as usize);
        let mut total_bytes = 0usize;
        let mut next_cursor = None;
        while let Some(row) = stream.try_next().await? {
            append_namespace_item(&mut items, &mut total_bytes, &mut next_cursor, row, limits)?;
        }
        let has_more = if let Some(cursor) = next_cursor.as_ref() {
            let exists = sqlx::query_scalar::<_, bool>(
                r#"
                SELECT EXISTS(
                    SELECT 1
                    FROM json_records
                    WHERE namespace = $1
                      AND (updated_at > $2::timestamptz
                           OR (updated_at = $2::timestamptz AND record_key > $3))
                )
                "#,
            )
            .bind(namespace)
            .bind(&cursor.updated_at)
            .bind(&cursor.updated_at)
            .bind(&cursor.record_key)
            .fetch_one(&self.pool)
            .await?;
            exists
        } else {
            false
        };
        Ok(NamespacePage {
            items,
            next_cursor: if has_more { next_cursor } else { None },
            has_more,
        })
    }

    pub async fn read_json<T: DeserializeOwned>(
        &self,
        namespace: &str,
        key: &str,
    ) -> Result<Option<T>, StorageError> {
        let row = sqlx::query_as::<_, (String,)>(
            "SELECT value_json FROM json_records WHERE namespace = $1 AND record_key = $2",
        )
        .bind(namespace)
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(value_json,)| serde_json::from_str(&value_json).map_err(StorageError::from))
            .transpose()
    }

    pub async fn delete_json(&self, namespace: &str, key: &str) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM json_records WHERE namespace = $1 AND record_key = $2")
            .bind(namespace)
            .bind(key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn count_namespace(&self, namespace: &str) -> Result<i64, StorageError> {
        let (count,) =
            sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM json_records WHERE namespace = $1")
                .bind(namespace)
                .fetch_one(&self.pool)
                .await?;
        Ok(count)
    }

    pub async fn delete_namespace(&self, namespace: &str) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM json_records WHERE namespace = $1")
            .bind(namespace)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn configured_pool_max_connections(env_key: &str, default: u32) -> u32 {
    env::var(env_key)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn configured_pool_timeout_seconds(env_key: &str, default: u64) -> u64 {
    env::var(env_key)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

impl DatabaseStore {
    pub async fn connect(url: &str) -> Result<Self, StorageError> {
        let config = DatabaseConfig::parse(url)?;
        match config.backend() {
            DatabaseBackend::Sqlite => Ok(Self::Sqlite(SqliteJsonStore::connect(url).await?)),
            DatabaseBackend::Postgres => Ok(Self::Postgres(PostgresJsonStore::connect(url).await?)),
        }
    }

    pub fn backend(&self) -> DatabaseBackend {
        match self {
            Self::Sqlite(_) => DatabaseBackend::Sqlite,
            Self::Postgres(_) => DatabaseBackend::Postgres,
        }
    }
}

async fn ensure_json_records_sqlite(pool: &Pool<Sqlite>) -> Result<(), StorageError> {
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
    .execute(pool)
    .await?;
    Ok(())
}

async fn ensure_json_records_postgres(pool: &Pool<Postgres>) -> Result<(), StorageError> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS json_records (
            namespace TEXT NOT NULL,
            record_key TEXT NOT NULL,
            value_json TEXT NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(namespace, record_key)
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

fn validated_identifier(value: &str) -> Result<&str, StorageError> {
    if value.is_empty()
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return Err(StorageError::UnsupportedDatabaseUrl);
    }
    Ok(value)
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

    pub fn read_directory_page<T: DeserializeOwned>(
        &self,
        directory: impl AsRef<Path>,
        cursor: Option<&JsonFilePageCursor>,
        requested_limit: Option<u32>,
        limits: QueryLimits,
    ) -> Result<JsonFilePage<T>, StorageError> {
        let limit = limits.normalize_limit(requested_limit)?;
        let directory = self.resolve(directory);
        let mut entries = Vec::new();
        for entry in fs::read_dir(directory)?.flatten() {
            if !entry.file_type()?.is_file()
                || entry.path().extension().and_then(|value| value.to_str()) != Some("json")
            {
                continue;
            }
            entries.push(entry);
            if entries.len() > limits.max_json_scan_entries {
                return Err(StorageError::PageScanTooLarge {
                    actual: entries.len(),
                    maximum: limits.max_json_scan_entries,
                });
            }
        }
        entries.sort_by_key(|entry| entry.file_name());

        let cursor_name = cursor.map(|value| value.entry_name.as_str());
        let mut items = Vec::with_capacity(limit as usize);
        let mut total_bytes = 0usize;
        let mut next_cursor = None;
        let mut has_more = false;

        for (index, entry) in entries
            .into_iter()
            .filter(|entry| match cursor_name {
                Some(cursor_name) => entry.file_name().to_string_lossy().as_ref() > cursor_name,
                None => true,
            })
            .enumerate()
        {
            if index >= limit as usize {
                has_more = true;
                break;
            }
            let entry_name = entry.file_name().to_string_lossy().into_owned();
            let bytes = fs::read(entry.path())?;
            if bytes.len() > limits.max_record_bytes {
                return Err(StorageError::RecordTooLarge {
                    actual: bytes.len(),
                    maximum: limits.max_record_bytes,
                });
            }
            total_bytes = total_bytes.saturating_add(bytes.len());
            if total_bytes > limits.max_page_bytes {
                return Err(StorageError::PageTooLarge {
                    actual: total_bytes,
                    maximum: limits.max_page_bytes,
                });
            }
            items.push(serde_json::from_slice(&bytes)?);
            next_cursor = Some(JsonFilePageCursor { entry_name });
        }

        if !has_more {
            next_cursor = None;
        }

        Ok(JsonFilePage {
            items,
            next_cursor,
            has_more,
        })
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

    pub fn write_resource_registration<T: Serialize>(
        &self,
        resource_did: &str,
        credential: &T,
    ) -> Result<(), StorageError> {
        self.write_credential(
            "resource-registration",
            "registrar",
            resource_did,
            "latest",
            credential,
        )?;
        self.store.write(
            Path::new("credentials")
                .join("resource-registrations")
                .join(did_to_file_name(resource_did)),
            credential,
        )
    }

    pub fn read_resource_registration<T: DeserializeOwned>(
        &self,
        resource_did: &str,
    ) -> Result<T, StorageError> {
        self.store.read(
            Path::new("credentials")
                .join("resource-registrations")
                .join(did_to_file_name(resource_did)),
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

