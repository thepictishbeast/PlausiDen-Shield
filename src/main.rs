//! PlausiDen Shield — unified operations platform for Linux servers.
//!
//! Single binary: `plausiden-shield [--config path] [--port N]`
//!
//! Serves a REST API + static frontend. All system commands go through
//! the safe executor layer (no shell injection). Six-layer access control
//! on every request.

mod api;

// Re-export from lib so `crate::X` works in api modules.
pub use plausiden_shield::{
    analytics, auth, config, db, executor, integrations, monitor, tickets, AppState,
};

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use clap::Parser;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    services::ServeDir,
    trace::TraceLayer,
};

/// PlausiDen Shield — Linux server operations platform.
#[derive(Parser)]
#[command(name = "plausiden-shield", version, about)]
struct Cli {
    /// Path to shield.toml configuration file.
    #[arg(short, long, default_value = "/etc/plausiden-shield/shield.toml")]
    config: PathBuf,

    /// Override bind port.
    #[arg(short, long)]
    port: Option<u16>,

    /// Override bind host.
    #[arg(long)]
    host: Option<String>,

    /// Override database path.
    #[arg(long)]
    db: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // Load configuration.
    let mut cfg = config::load_config(&cli.config)?;

    // Apply CLI overrides.
    if let Some(port) = cli.port {
        cfg.server.port = port;
    }
    if let Some(host) = cli.host {
        cfg.server.host = host;
    }
    if let Some(db_path) = cli.db {
        cfg.database.path = db_path;
    }

    // Ensure database directory exists.
    if let Some(parent) = cfg.database.path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Open database and run migrations.
    let database = db::Database::open(&cfg.database.path)?;

    // Seed admin user if database is empty.
    auth::session::seed_admin_if_empty(&database).await?;

    // Initialize system info collector.
    let system = Arc::new(tokio::sync::Mutex::new(sysinfo::System::new_all()));

    // Build integration bus.
    let bus = integrations::IntegrationBus::new();
    let registered = integrations::build_from_config(&cfg.integrations.services);
    for integration in registered {
        bus.register(integration).await;
    }

    let app_state = AppState {
        db: database.clone(),
        config: Arc::new(cfg.clone()),
        system: system.clone(),
        integrations: Arc::new(bus),
    };

    // Start background monitor.
    monitor::start_monitor(database, system, 60).await?;

    // Build router.
    let app = Router::new()
        .merge(api::router())
        .fallback_service(ServeDir::new(&cfg.server.frontend_dir))
        .layer(CompressionLayer::new())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    let addr = SocketAddr::new(
        cfg.server.host.parse().unwrap_or([127, 0, 0, 1].into()),
        cfg.server.port,
    );

    tracing::info!(%addr, "Shield starting");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
