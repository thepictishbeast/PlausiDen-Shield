//! Analytics and metrics API.
//!
//! Serves historical metric data from SQLite for the dashboard charts,
//! and provides audit log queries.
#![allow(dead_code)]

use anyhow::{Context, Result};
use serde::Serialize;

use crate::db::Database;

#[derive(Debug, Clone, Serialize)]
pub struct MetricPoint {
    pub value: f64,
    pub recorded_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub user_id: Option<i64>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub outcome: String,
    pub ip_address: Option<String>,
    pub created_at: String,
}

/// Get recent metric values for a given type and name.
pub async fn get_metrics(
    db: &Database,
    metric_type: &str,
    metric_name: &str,
    limit: u32,
) -> Result<Vec<MetricPoint>> {
    let mt = metric_type.to_string();
    let mn = metric_name.to_string();

    db.call(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT value, recorded_at FROM metrics \
             WHERE metric_type = ?1 AND metric_name = ?2 \
             ORDER BY recorded_at DESC LIMIT ?3",
        )?;
        let points = stmt
            .query_map(rusqlite::params![mt, mn, limit], |row| {
                Ok(MetricPoint {
                    value: row.get(0)?,
                    recorded_at: row.get(1)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(points)
    })
    .await
}

/// Get recent audit log entries.
pub async fn get_audit_log(db: &Database, limit: u32) -> Result<Vec<AuditEntry>> {
    db.call(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, user_id, action, resource_type, resource_id, outcome, ip_address, created_at \
             FROM audit_log ORDER BY created_at DESC LIMIT ?1",
        )?;
        let entries = stmt
            .query_map(rusqlite::params![limit], |row| {
                Ok(AuditEntry {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    action: row.get(2)?,
                    resource_type: row.get(3)?,
                    resource_id: row.get(4)?,
                    outcome: row.get(5)?,
                    ip_address: row.get(6)?,
                    created_at: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(entries)
    })
    .await
}

/// Log an audit entry.
#[allow(clippy::too_many_arguments)]
pub async fn log_audit(
    db: &Database,
    user_id: Option<i64>,
    action: &str,
    resource_type: Option<&str>,
    resource_id: Option<&str>,
    outcome: &str,
    ip_address: Option<&str>,
    policy_chain: Option<&str>,
) -> Result<()> {
    let action = action.to_string();
    let rt = resource_type.map(|s| s.to_string());
    let ri = resource_id.map(|s| s.to_string());
    let outcome = outcome.to_string();
    let ip = ip_address.map(|s| s.to_string());
    let pc = policy_chain.map(|s| s.to_string());

    db.call(move |conn| {
        conn.execute(
            "INSERT INTO audit_log (user_id, action, resource_type, resource_id, outcome, ip_address, policy_chain) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![user_id, action, rt, ri, outcome, ip, pc],
        )
        .context("Failed to log audit entry")?;
        Ok(())
    })
    .await
}
