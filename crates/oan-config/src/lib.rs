// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use anyhow::{bail, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub type Environment = BTreeMap<String, String>;

#[derive(Clone, Copy)]
pub enum Kind {
    String,
    Bool,
    U64,
    I64,
    Float,
    List,
}

#[derive(Clone, Copy)]
pub struct Field {
    pub path: &'static str,
    pub kind: Kind,
}

pub struct Loaded<T> {
    pub value: T,
    pub sources: BTreeMap<String, String>,
    pub warnings: Vec<String>,
}

impl<T: std::fmt::Debug> std::fmt::Debug for Loaded<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Loaded(<configuration hidden>)")
    }
}

#[derive(clap::Parser, Debug)]
#[command(version, about = "OAN node service and configuration tools")]
pub struct NodeCli {
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,
    #[arg(value_name = "CONFIG", conflicts_with = "config")]
    pub legacy_config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Option<NodeCommand>,
}

#[derive(clap::Subcommand, Debug)]
pub enum NodeCommand {
    CheckConfig,
    PrintEffectiveConfig,
    SemanticRebuild(SemanticArgs),
    SemanticBackfillSkipped(SemanticArgs),
    SemanticEvaluate(EvaluationArgs),
    SemanticRebuildEvaluate(EvaluationArgs),
}

#[derive(clap::Args, Debug)]
pub struct SemanticArgs {
    #[arg(conflicts_with = "config")]
    pub path: Option<PathBuf>,
    #[arg(long, default_value = "both", value_parser = ["both", "context", "intent"])]
    pub stage: String,
    #[arg(long)]
    pub reset: bool,
}

#[derive(clap::Args, Debug)]
pub struct EvaluationArgs {
    #[arg(conflicts_with = "config")]
    pub path: Option<PathBuf>,
    pub suite: Option<PathBuf>,
    #[arg(long = "suite", conflicts_with = "suite")]
    pub suite_file: Option<PathBuf>,
}

impl EvaluationArgs {
    pub fn suite_path(self, default: &str) -> PathBuf {
        self.suite_file
            .or(self.suite)
            .unwrap_or_else(|| default.into())
    }
}

impl NodeCli {
    pub fn parse() -> Self {
        <Self as clap::Parser>::parse()
    }
    pub fn path(&self, default: &str) -> Result<PathBuf> {
        let nested = match &self.command {
            Some(NodeCommand::SemanticRebuild(a) | NodeCommand::SemanticBackfillSkipped(a)) => {
                a.path.as_ref()
            }
            Some(NodeCommand::SemanticEvaluate(a) | NodeCommand::SemanticRebuildEvaluate(a)) => {
                a.path.as_ref()
            }
            _ => None,
        };
        if self.legacy_config.is_some() && (self.config.is_some() || nested.is_some()) {
            bail!("configuration path specified more than once");
        }
        Ok(self
            .config
            .as_ref()
            .or(nested)
            .or(self.legacy_config.as_ref())
            .cloned()
            .unwrap_or_else(|| default.into()))
    }
    pub fn inspect<T: Serialize>(
        &self,
        config: &T,
        sources: &BTreeMap<String, String>,
    ) -> Result<bool> {
        match self.command {
            Some(NodeCommand::CheckConfig) => {
                println!("Configuration valid");
                Ok(true)
            }
            Some(NodeCommand::PrintEffectiveConfig) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&effective(config, sources)?)?
                );
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

fn key(value: &str) -> String {
    value
        .chars()
        .filter(|c| *c != '_')
        .flat_map(char::to_lowercase)
        .collect()
}

fn field<'a>(path: &str, fields: &'a [Field]) -> Option<&'a Field> {
    fields.iter().find(|f| key(f.path) == key(path))
}

fn set(value: &mut Value, path: &str, input: Value) -> Result<()> {
    let mut target = value;
    let parts: Vec<_> = path.split('.').collect();
    for part in &parts[..parts.len() - 1] {
        target = target
            .as_object_mut()
            .context("configuration section must be a table")?
            .entry((*part).to_owned())
            .or_insert_with(|| json!({}));
    }
    target
        .as_object_mut()
        .context("configuration section must be a table")?
        .insert(parts[parts.len() - 1].to_owned(), input);
    Ok(())
}

fn normalize(
    value: &Value,
    prefix: &str,
    fields: &[Field],
    output: &mut Value,
    sources: &mut BTreeMap<String, String>,
    source: &str,
) -> Result<()> {
    if let Some(table) = value.as_object() {
        if !prefix.is_empty()
            && !fields
                .iter()
                .any(|f| key(f.path).starts_with(&(key(prefix) + ".")))
        {
            bail!("unknown configuration section: {prefix}");
        }
        if table.is_empty() && !prefix.is_empty() {
            let canonical = fields
                .iter()
                .find_map(|f| {
                    let parts: Vec<_> = f.path.split('.').collect();
                    let depth = prefix.split('.').count();
                    if parts.len() <= depth {
                        return None;
                    }
                    let candidate = parts[..depth].join(".");
                    (key(&candidate) == key(prefix)).then_some(candidate)
                })
                .context("unknown configuration table")?;
            set(output, &canonical, json!({}))?;
        }
        for (name, value) in table {
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}.{name}")
            };
            if value.is_object() {
                let depth = path.split('.').count();
                let canonical = fields
                    .iter()
                    .find_map(|f| {
                        let parts: Vec<_> = f.path.split('.').collect();
                        if parts.len() <= depth {
                            return None;
                        }
                        let candidate = parts[..depth].join(".");
                        (key(&candidate) == key(&path)).then_some(candidate)
                    })
                    .with_context(|| format!("unknown configuration section: {path}"))?;
                let marker = format!("@table:{canonical}");
                if sources.insert(marker, source.to_owned()).is_some() {
                    bail!("duplicate configuration section: {canonical}");
                }
            }
            normalize(value, &path, fields, output, sources, source)?;
        }
    } else {
        let specification = field(prefix, fields)
            .with_context(|| format!("unknown configuration field: {prefix}"))?;
        let canonical = specification.path;
        let valid = match specification.kind {
            Kind::String => value.is_string(),
            Kind::Bool => value.is_boolean(),
            Kind::U64 => value.as_u64().is_some(),
            Kind::I64 => value.as_i64().is_some(),
            Kind::Float => value.is_number(),
            Kind::List => value.is_array(),
        };
        if !valid {
            bail!("invalid configuration field type: {canonical} (value hidden)");
        }
        if sources.contains_key(canonical) {
            bail!("duplicate configuration field: {canonical}");
        }
        set(output, canonical, value.clone())?;
        sources.insert(canonical.to_owned(), source.to_owned());
    }
    Ok(())
}

fn parse_scalar(value: &str, field: &Field) -> Result<Value> {
    let invalid = || {
        anyhow::anyhow!(
            "invalid environment value for {} (value hidden)",
            field.path
        )
    };
    Ok(match field.kind {
        Kind::String => Value::String(value.to_owned()),
        Kind::Bool => Value::Bool(value.parse().map_err(|_| invalid())?),
        Kind::U64 => json!(value.parse::<u64>().map_err(|_| invalid())?),
        Kind::I64 => json!(value.parse::<i64>().map_err(|_| invalid())?),
        Kind::Float => json!(value.parse::<f64>().map_err(|_| invalid())?),
        Kind::List => bail!("environment lists are not supported: {}", field.path),
    })
}

pub fn load<T: DeserializeOwned>(
    path: &Path,
    prefix: &str,
    fields: &[Field],
    environment: &Environment,
    legacy_pool: bool,
) -> Result<Loaded<T>> {
    let path = absolute(path)?;
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read UTF-8 configuration: {}", path.display()))?;
    let raw: toml::Value = toml::from_str(&text).map_err(|err| {
        anyhow::anyhow!(
            "invalid TOML configuration at byte range {:?} (input hidden)",
            err.span()
        )
    })?;
    let mut merged = json!({});
    let mut sources = BTreeMap::new();
    normalize(
        &serde_json::to_value(raw)?,
        "",
        fields,
        &mut merged,
        &mut sources,
        &format!("file:{}", path.display()),
    )?;
    let mut warnings = Vec::new();
    if legacy_pool {
        let url = environment
            .iter()
            .find_map(|(name, value)| {
                name.strip_prefix(&format!("{prefix}__"))
                    .is_some_and(|suffix| {
                        key(&suffix.replace("__", ".")) == key("paths.database_url")
                    })
                    .then_some(value.as_str())
            })
            .or_else(|| {
                merged
                    .pointer("/paths/database_url")
                    .and_then(Value::as_str)
            })
            .unwrap_or("");
        let backend = if url.starts_with("postgres:") || url.starts_with("postgresql:") {
            Some(("POSTGRES", 8))
        } else if url.starts_with("sqlite:") {
            Some(("SQLITE", 32))
        } else {
            None
        };
        if let Some((backend, default_max)) = backend {
            for (suffix, target, default, max) in [
                (
                    "MAX_CONNECTIONS",
                    "database.pool.max_connections",
                    default_max,
                    u32::MAX as u64,
                ),
                (
                    "ACQUIRE_TIMEOUT_SECONDS",
                    "database.pool.acquire_timeout_seconds",
                    30,
                    u64::MAX,
                ),
            ] {
                let name = format!("OAN_{backend}_{suffix}");
                if let Some(raw) = environment.get(&name) {
                    let parsed = raw.parse::<u64>().ok().filter(|v| *v > 0 && *v <= max);
                    warnings.push(format!(
                        "deprecated environment variable: {name}{}",
                        if parsed.is_none() {
                            "; invalid value, using legacy default"
                        } else {
                            ""
                        }
                    ));
                    set(&mut merged, target, json!(parsed.unwrap_or(default)))?;
                    sources.insert(target.to_owned(), format!("environment:{name}"));
                }
            }
        }
    }
    let boundary = format!("{prefix}__");
    let mut env_fields = BTreeMap::new();
    for (name, value) in environment {
        if let Some(suffix) = name.strip_prefix(&boundary) {
            let path = suffix.replace("__", ".");
            let specification = field(&path, fields)
                .with_context(|| format!("unknown configuration environment variable: {name}"))?;
            if env_fields.insert(specification.path, name).is_some() {
                bail!(
                    "duplicate environment configuration field: {}",
                    specification.path
                );
            }
            set(
                &mut merged,
                specification.path,
                parse_scalar(value, specification)?,
            )?;
            sources.insert(specification.path.to_owned(), format!("environment:{name}"));
        }
    }
    // config owns the merged source; typed defaults are applied only at deserialization.
    let source = serde_json::to_string(&merged)?;
    let combined = config::Config::builder()
        .add_source(config::File::from_str(&source, config::FileFormat::Json))
        .build()
        .map_err(|_| anyhow::anyhow!("cannot merge configuration (values hidden)"))?;
    let merged: Value = combined
        .try_deserialize()
        .map_err(|_| anyhow::anyhow!("cannot decode configuration (values hidden)"))?;
    let value = serde_path_to_error::deserialize(merged).map_err(|err| {
        anyhow::anyhow!(
            "invalid configuration field {} (details hidden)",
            err.path()
        )
    })?;
    Ok(Loaded {
        value,
        sources,
        warnings,
    })
}

pub fn absolute(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut resolved = PathBuf::new();
    for part in path.components() {
        match part {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                resolved.pop();
            }
            other => resolved.push(other.as_os_str()),
        }
    }
    Ok(resolved)
}

pub fn environment() -> Environment {
    std::env::vars_os()
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .collect()
}

pub fn validate_http_endpoint(name: &str, endpoint: &str) -> Result<()> {
    let url =
        url::Url::parse(endpoint).map_err(|_| anyhow::anyhow!("invalid {name} (value hidden)"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        bail!("invalid {name}: HTTP(S) URL required (value hidden)");
    }
    Ok(())
}

pub fn effective<T: Serialize>(value: &T, sources: &BTreeMap<String, String>) -> Result<Value> {
    fn walk(
        value: &mut Value,
        path: &str,
        sources: &BTreeMap<String, String>,
        origins: &mut BTreeMap<String, String>,
    ) {
        if let Some(table) = value.as_object_mut() {
            for (name, value) in table {
                let path = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}.{name}")
                };
                walk(value, &path, sources, origins);
            }
        } else {
            origins.insert(
                path.to_owned(),
                sources
                    .get(path)
                    .cloned()
                    .unwrap_or_else(|| "code-default".to_owned()),
            );
            let lower = path.to_ascii_lowercase();
            if [
                "token",
                "password",
                "secret",
                "private_key",
                "database_url",
                "endpoint",
            ]
            .iter()
            .any(|part| lower.contains(part))
            {
                if !value.is_null() {
                    *value = json!("<redacted>");
                }
            }
        }
    }
    let mut config = serde_json::to_value(value)?;
    let mut origins = BTreeMap::new();
    walk(&mut config, "", sources, &mut origins);
    Ok(json!({"config": config, "sources": origins}))
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TokioConfig {
    pub worker_threads: Option<usize>,
    pub thread_stack_size_mib: Option<usize>,
    pub max_blocking_threads: Option<usize>,
}

impl TokioConfig {
    pub fn validate(&self) -> Result<()> {
        for (name, value, maximum) in [
            ("worker_threads", self.worker_threads, 1024),
            ("max_blocking_threads", self.max_blocking_threads, 65536),
            ("thread_stack_size_mib", self.thread_stack_size_mib, 1024),
        ] {
            if value.is_some_and(|v| v == 0 || v > maximum) {
                bail!("runtime.tokio.{name} must be between 1 and {maximum}");
            }
        }
        self.stack_bytes()?;
        Ok(())
    }
    pub fn stack_bytes(&self) -> Result<Option<usize>> {
        self.thread_stack_size_mib
            .map(|mib| {
                mib.checked_mul(1024 * 1024)
                    .context("runtime.tokio.thread_stack_size_mib overflow")
            })
            .transpose()
    }
}

pub const TOKIO_FIELDS: &[Field] = &[
    Field {
        path: "runtime.tokio.worker_threads",
        kind: Kind::U64,
    },
    Field {
        path: "runtime.tokio.thread_stack_size_mib",
        kind: Kind::U64,
    },
    Field {
        path: "runtime.tokio.max_blocking_threads",
        kind: Kind::U64,
    },
];

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DatabaseConfig {
    pub pool: PoolConfig,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PoolConfig {
    pub max_connections: Option<u32>,
    pub acquire_timeout_seconds: Option<u64>,
    pub idle_timeout_seconds: Option<u64>,
    pub max_lifetime_seconds: Option<u64>,
}

impl PoolConfig {
    pub fn resolve(&mut self, url: Option<&str>) -> Result<()> {
        let Some(url) = url.filter(|u| !u.is_empty()) else {
            return self.validate();
        };
        let postgres = url.starts_with("postgres:") || url.starts_with("postgresql:");
        let sqlite = url.starts_with("sqlite:");
        if !postgres && !sqlite {
            bail!("unsupported paths.database_url (value hidden)");
        }
        if sqlite && (self.idle_timeout_seconds.is_some() || self.max_lifetime_seconds.is_some()) {
            bail!("database.pool lifecycle options are supported only for PostgreSQL");
        }
        self.max_connections
            .get_or_insert(if postgres { 8 } else { 32 });
        self.acquire_timeout_seconds.get_or_insert(30);
        if postgres {
            self.idle_timeout_seconds.get_or_insert(30);
            self.max_lifetime_seconds.get_or_insert(300);
        }
        self.validate()
    }
    fn validate(&self) -> Result<()> {
        if self.max_connections == Some(0) || self.acquire_timeout_seconds == Some(0) {
            bail!("database.pool connections and acquire timeout must be positive");
        }
        Ok(())
    }
}

pub const DATABASE_FIELDS: &[Field] = &[
    Field {
        path: "database.pool.max_connections",
        kind: Kind::U64,
    },
    Field {
        path: "database.pool.acquire_timeout_seconds",
        kind: Kind::U64,
    },
    Field {
        path: "database.pool.idle_timeout_seconds",
        kind: Kind::U64,
    },
    Field {
        path: "database.pool.max_lifetime_seconds",
        kind: Kind::U64,
    },
];

