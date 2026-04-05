//! Database and migration tests.
//!
//! All tests use in-memory SQLite — no disk I/O.

use plausiden_shield::db::Database;
use rusqlite::Connection;

fn with_conn_sync(db: &Database, f: impl FnOnce(&Connection) -> anyhow::Result<()>) {
    db.with_conn(f).unwrap();
}

#[test]
fn schema_creates_all_tables() {
    let db = Database::open_memory().unwrap();
    with_conn_sync(&db, |conn| {
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")?
            .query_map([], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        assert!(tables.contains(&"users".to_string()));
        assert!(tables.contains(&"sessions".to_string()));
        assert!(tables.contains(&"audit_log".to_string()));
        assert!(tables.contains(&"tickets".to_string()));
        assert!(tables.contains(&"ticket_comments".to_string()));
        assert!(tables.contains(&"metrics".to_string()));
        assert!(tables.contains(&"policies".to_string()));
        assert!(tables.contains(&"integration_state".to_string()));
        Ok(())
    });
}

#[test]
fn migration_is_idempotent() {
    let db = Database::open_memory().unwrap();
    with_conn_sync(&db, |conn| {
        let sql = include_str!("../migrations/001_initial.sql");
        conn.execute_batch(sql)?;
        Ok(())
    });
}

#[test]
fn indexes_exist() {
    let db = Database::open_memory().unwrap();
    with_conn_sync(&db, |conn| {
        let indexes: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'")?
            .query_map([], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        assert!(indexes.contains(&"idx_sessions_user".to_string()));
        assert!(indexes.contains(&"idx_sessions_expiry".to_string()));
        assert!(indexes.contains(&"idx_audit_user".to_string()));
        assert!(indexes.contains(&"idx_audit_action".to_string()));
        assert!(indexes.contains(&"idx_audit_created".to_string()));
        assert!(indexes.contains(&"idx_tickets_status".to_string()));
        assert!(indexes.contains(&"idx_tickets_creator".to_string()));
        assert!(indexes.contains(&"idx_comments_ticket".to_string()));
        assert!(indexes.contains(&"idx_metrics_type".to_string()));
        Ok(())
    });
}

#[test]
fn foreign_keys_enforced() {
    let db = Database::open_memory().unwrap();
    with_conn_sync(&db, |conn| {
        let result = conn.execute(
            "INSERT INTO tickets (title, description, created_by) VALUES ('test', 'desc', 999)",
            [],
        );
        assert!(result.is_err(), "FK constraint should reject nonexistent user");
        Ok(())
    });
}

#[test]
fn user_role_check_constraint() {
    let db = Database::open_memory().unwrap();
    with_conn_sync(&db, |conn| {
        let result = conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES ('x', 'hash', 'superadmin')",
            [],
        );
        assert!(result.is_err(), "CHECK constraint should reject invalid role");
        Ok(())
    });
}

#[test]
fn ticket_status_check_constraint() {
    let db = Database::open_memory().unwrap();
    with_conn_sync(&db, |conn| {
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES ('test', 'hash')",
            [],
        )?;
        let result = conn.execute(
            "INSERT INTO tickets (title, description, status, created_by) VALUES ('t', 'd', 'invalid', 1)",
            [],
        );
        assert!(result.is_err(), "CHECK constraint should reject invalid status");
        Ok(())
    });
}

#[tokio::test]
async fn db_call_async_works() {
    let db = Database::open_memory().unwrap();
    let count: i64 = db
        .call(|conn: &Connection| {
            conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
                .map_err(Into::into)
        })
        .await
        .unwrap();
    assert_eq!(count, 0);
}
