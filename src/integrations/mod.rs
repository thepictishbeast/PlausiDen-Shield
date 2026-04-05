//! Integration layer — the hub architecture.
//!
//! Shield consumes external services via the `Integration` trait.
//! Each integration can pull data from an external API, push commands,
//! and report health status. Integrations are config-driven and loaded
//! from `integrations.toml`.
//!
//! Dual-mode design:
//!   - Integrated: talks to external API (e.g., Sacred.Vote, Grafana)
//!   - Standalone: uses local SQLite fallback

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::IntegrationEntry;

/// Health status of an integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Error,
    Unknown,
}

/// Result of a health check.
#[derive(Debug, Clone, Serialize)]
pub struct HealthReport {
    pub name: String,
    pub status: HealthStatus,
    pub message: Option<String>,
    pub latency_ms: Option<u64>,
    pub checked_at: String,
}

/// The Integration trait — implemented by each external service connector.
#[async_trait]
pub trait Integration: Send + Sync {
    /// Human-readable name.
    fn name(&self) -> &str;

    /// Check if the external service is reachable and healthy.
    async fn health_check(&self) -> Result<HealthReport>;

    /// Pull data from the external service (e.g., sync metrics, fetch status).
    async fn pull(&self) -> Result<serde_json::Value>;

    /// Push a command or data to the external service.
    async fn push(&self, payload: serde_json::Value) -> Result<serde_json::Value>;
}

/// The integration bus — manages all registered integrations.
pub struct IntegrationBus {
    integrations: Arc<RwLock<HashMap<String, Box<dyn Integration>>>>,
}

impl Default for IntegrationBus {
    fn default() -> Self {
        Self::new()
    }
}

impl IntegrationBus {
    pub fn new() -> Self {
        Self {
            integrations: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register an integration.
    pub async fn register(&self, integration: Box<dyn Integration>) {
        let name = integration.name().to_string();
        self.integrations.write().await.insert(name, integration);
    }

    /// Run health checks on all integrations.
    pub async fn health_check_all(&self) -> Vec<HealthReport> {
        let integrations = self.integrations.read().await;
        let mut reports = Vec::new();

        for (_, integration) in integrations.iter() {
            match integration.health_check().await {
                Ok(report) => reports.push(report),
                Err(e) => reports.push(HealthReport {
                    name: integration.name().to_string(),
                    status: HealthStatus::Error,
                    message: Some(e.to_string()),
                    latency_ms: None,
                    checked_at: chrono::Utc::now().to_rfc3339(),
                }),
            }
        }

        reports
    }

    /// Get health for a specific integration.
    pub async fn health_check(&self, name: &str) -> Option<HealthReport> {
        let integrations = self.integrations.read().await;
        if let Some(integration) = integrations.get(name) {
            Some(
                integration
                    .health_check()
                    .await
                    .unwrap_or_else(|e| HealthReport {
                        name: name.to_string(),
                        status: HealthStatus::Error,
                        message: Some(e.to_string()),
                        latency_ms: None,
                        checked_at: chrono::Utc::now().to_rfc3339(),
                    }),
            )
        } else {
            None
        }
    }

    /// List registered integration names.
    pub async fn list(&self) -> Vec<String> {
        self.integrations.read().await.keys().cloned().collect()
    }
}

/// Build integrations from config entries.
pub fn build_from_config(
    _entries: &HashMap<String, IntegrationEntry>,
) -> Vec<Box<dyn Integration>> {
    // Integrations are registered here as they're implemented.
    // For now, return empty — each integration module will register itself.
    Vec::new()
}
