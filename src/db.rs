//! Database abstraction over rusqlite.
//!
//! Wraps a `rusqlite::Connection` behind a `std::sync::Mutex` and provides
//! async helpers that offload blocking SQLite I/O onto `spawn_blocking`.

use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Thread-safe database handle.
#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    /// Open (or create) a SQLite database at `path` and apply migrations.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("Failed to open database: {}", path.display()))?;

        // WAL mode for better concurrent read performance.
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.migrate()?;
        Ok(db)
    }

    /// Open an in-memory database (for tests).
    #[cfg(test)]
    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.migrate()?;
        Ok(db)
    }

    /// Run a closure with a reference to the underlying connection.
    ///
    /// This acquires the mutex synchronously, so callers should wrap in
    /// `tokio::task::spawn_blocking` for async contexts.
    pub fn with_conn<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("Database mutex poisoned: {}", e))?;
        f(&conn)
    }

    /// Async wrapper: runs a closure on the blocking thread pool.
    pub async fn call<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let db = self.clone();
        tokio::task::spawn_blocking(move || db.with_conn(f))
            .await
            .context("Database task panicked")?
    }

    /// Apply all migrations.
    fn migrate(&self) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("Database mutex poisoned: {}", e))?;

        conn.execute_batch(include_str!("../migrations/001_initial.sql"))
            .context("Failed to apply migration 001_initial.sql")?;

        tracing::info!("Database migrations applied");
        Ok(())
    }
}
