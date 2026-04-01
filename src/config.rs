//! Configuration loading and structs.
//!
//! Shield's configuration is split across two files:
//! - `/etc/plausiden-shield/shield.toml` — server settings, bind address, DB path
//! - `/etc/plausiden-shield/integrations.toml` — external service connections
//!
//! All paths can be overridden via CLI flags.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Top-level Shield configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ShieldConfig {
    /// Server settings.
    #[serde(default)]
    pub server: ServerConfig,

    /// Database settings.
    #[serde(default)]
    pub database: DatabaseConfig,

    /// Authentication settings.
    #[serde(default)]
    pub auth: AuthConfig,

    /// Integration definitions.
    #[serde(default)]
    pub integrations: IntegrationsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Bind address (default: 127.0.0.1).
    #[serde(default = "default_bind_host")]
    pub host: String,

    /// Bind port (default: 9443).
    #[serde(default = "default_bind_port")]
    pub port: u16,

    /// Path to the frontend static assets directory.
    #[serde(default = "default_frontend_dir")]
    pub frontend_dir: PathBuf,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_bind_host(),
            port: default_bind_port(),
            frontend_dir: default_frontend_dir(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    /// Path to the SQLite database file.
    #[serde(default = "default_db_path")]
    pub path: PathBuf,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: default_db_path(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    /// Session timeout in minutes (default: 60).
    #[serde(default = "default_session_timeout")]
    pub session_timeout_minutes: u64,

    /// Whether to require 2FA for admin accounts.
    #[serde(default)]
    pub require_admin_2fa: bool,

    /// Path to policy files directory.
    #[serde(default = "default_policies_dir")]
    pub policies_dir: PathBuf,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            session_timeout_minutes: default_session_timeout(),
            require_admin_2fa: false,
            policies_dir: default_policies_dir(),
        }
    }
}

/// Integration configuration — defines external services Shield connects to.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct IntegrationsConfig {
    /// Named integrations.
    #[serde(flatten)]
    pub services: HashMap<String, IntegrationEntry>,
}

/// A single integration entry.
#[derive(Debug, Clone, Deserialize)]
pub struct IntegrationEntry {
    /// Whether this integration is active.
    #[serde(default)]
    pub enabled: bool,

    /// Base URL for the external service API.
    pub base_url: Option<String>,

    /// Environment variable name containing the auth token/code.
    pub auth_env: Option<String>,

    /// Named API endpoints.
    #[serde(default)]
    pub endpoints: HashMap<String, String>,

    /// Poll interval in seconds for health checks.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_seconds: u64,

    /// For file-based integrations (e.g., vulnscan reports).
    pub binary_path: Option<PathBuf>,
    pub report_dir: Option<PathBuf>,
}

// --- Defaults ---

fn default_bind_host() -> String {
    "127.0.0.1".to_string()
}
fn default_bind_port() -> u16 {
    9443
}
fn default_frontend_dir() -> PathBuf {
    PathBuf::from("/usr/share/plausiden-shield/frontend")
}
fn default_db_path() -> PathBuf {
    PathBuf::from("/var/lib/plausiden-shield/shield.db")
}
fn default_session_timeout() -> u64 {
    60
}
fn default_policies_dir() -> PathBuf {
    PathBuf::from("/etc/plausiden-shield/policies")
}
fn default_poll_interval() -> u64 {
    60
}

/// Load configuration from a TOML file.
pub fn load_config(path: &Path) -> Result<ShieldConfig> {
    if !path.exists() {
        tracing::warn!(
            path = %path.display(),
            "Config file not found, using defaults"
        );
        return Ok(ShieldConfig {
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            auth: AuthConfig::default(),
            integrations: IntegrationsConfig::default(),
        });
    }

    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config: {}", path.display()))?;
    let config: ShieldConfig =
        toml::from_str(&contents).with_context(|| "Failed to parse shield.toml")?;
    tracing::info!(path = %path.display(), "Configuration loaded");
    Ok(config)
}
