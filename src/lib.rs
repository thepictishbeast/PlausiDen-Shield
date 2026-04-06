//! PlausiDen Shield — unified operations platform for Linux servers.
//!
//! Library crate exposing core modules for integration tests.

#![forbid(unsafe_code)]

pub mod analytics;
pub mod auth;
pub mod config;
pub mod db;
pub mod executor;
pub mod integrations;
pub mod monitor;
pub mod tickets;

use std::sync::Arc;

/// Shared application state available to all handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: db::Database,
    pub config: Arc<config::ShieldConfig>,
    pub system: Arc<tokio::sync::Mutex<sysinfo::System>>,
    pub integrations: Arc<integrations::IntegrationBus>,
}
