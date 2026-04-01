//! System monitoring — periodic metric collection and alerting.
//!
//! Runs a background task that samples CPU, memory, disk, and network
//! metrics at a configurable interval and stores them in SQLite for
//! the analytics dashboard.

use anyhow::Result;
use std::sync::Arc;
use sysinfo::System;
use tokio::sync::Mutex;

use crate::db::Database;

/// Start the background monitoring loop.
pub async fn start_monitor(
    db: Database,
    system: Arc<Mutex<System>>,
    interval_seconds: u64,
) -> Result<()> {
    let interval = tokio::time::Duration::from_secs(interval_seconds);

    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        loop {
            tick.tick().await;
            if let Err(e) = collect_metrics(&db, &system).await {
                tracing::error!(error = %e, "Metric collection failed");
            }
        }
    });

    tracing::info!(
        interval_seconds = interval_seconds,
        "Background monitor started"
    );
    Ok(())
}

async fn collect_metrics(db: &Database, system: &Arc<Mutex<System>>) -> Result<()> {
    let mut sys = system.lock().await;
    sys.refresh_all();

    let cpu_usage = if sys.cpus().is_empty() {
        0.0
    } else {
        sys.cpus().iter().map(|c| c.cpu_usage() as f64).sum::<f64>() / sys.cpus().len() as f64
    };

    let total_mem = sys.total_memory() as f64;
    let used_mem = sys.used_memory() as f64;
    let mem_percent = if total_mem > 0.0 {
        (used_mem / total_mem) * 100.0
    } else {
        0.0
    };

    drop(sys); // Release lock before async DB call.

    let cpu = cpu_usage;
    let mem = mem_percent;

    db.call(move |conn| {
        conn.execute(
            "INSERT INTO metrics (metric_type, metric_name, value) VALUES ('cpu', 'usage_percent', ?1)",
            rusqlite::params![cpu],
        )?;
        conn.execute(
            "INSERT INTO metrics (metric_type, metric_name, value) VALUES ('memory', 'usage_percent', ?1)",
            rusqlite::params![mem],
        )?;
        Ok(())
    })
    .await?;

    Ok(())
}
