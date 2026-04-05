//! Authentication and authorization tests.
//!
//! Tests password hashing, session lifecycle, RBAC permissions,
//! and the six-layer policy engine.

use plausiden_shield::auth::rbac::{Permission, Role};
use plausiden_shield::auth::session;
use plausiden_shield::db::Database;

// --- Password hashing ---

#[test]
fn hash_and_verify_password() {
    let hash = session::hash_password("correct-horse-battery-staple").unwrap();
    assert!(session::verify_password("correct-horse-battery-staple", &hash).unwrap());
    assert!(!session::verify_password("wrong-password", &hash).unwrap());
}

#[test]
fn hash_is_unique_each_time() {
    let h1 = session::hash_password("same-password").unwrap();
    let h2 = session::hash_password("same-password").unwrap();
    assert_ne!(h1, h2, "Different salts should produce different hashes");
}

// --- RBAC ---

#[test]
fn admin_has_all_permissions() {
    assert!(Role::Admin.has_permission(Permission::ManageFirewall));
    assert!(Role::Admin.has_permission(Permission::ManageUsers));
    assert!(Role::Admin.has_permission(Permission::WebTerminal));
    assert!(Role::Admin.has_permission(Permission::ExportData));
}

#[test]
fn client_has_minimal_permissions() {
    assert!(Role::Client.has_permission(Permission::ViewDashboard));
    assert!(Role::Client.has_permission(Permission::CreateTicket));
    assert!(Role::Client.has_permission(Permission::ViewOwnTickets));
    assert!(!Role::Client.has_permission(Permission::ManageFirewall));
    assert!(!Role::Client.has_permission(Permission::EditFiles));
    assert!(!Role::Client.has_permission(Permission::ManageUsers));
    assert!(!Role::Client.has_permission(Permission::WebTerminal));
}

#[test]
fn operator_cannot_manage_users() {
    assert!(!Role::Operator.has_permission(Permission::ManageUsers));
    assert!(!Role::Operator.has_permission(Permission::ManageRoles));
    assert!(!Role::Operator.has_permission(Permission::ManagePolicies));
    assert!(Role::Operator.has_permission(Permission::ManageFirewall));
    assert!(Role::Operator.has_permission(Permission::ManageServices));
}

#[test]
fn support_can_manage_tickets() {
    assert!(Role::Support.has_permission(Permission::ManageTickets));
    assert!(Role::Support.has_permission(Permission::ViewAllTickets));
    assert!(!Role::Support.has_permission(Permission::ManageFirewall));
    assert!(!Role::Support.has_permission(Permission::EditFiles));
}

#[test]
fn role_level_ordering() {
    assert!(Role::Admin.level() > Role::Operator.level());
    assert!(Role::Operator.level() > Role::Support.level());
    assert!(Role::Support.level() > Role::Client.level());
}

#[test]
fn role_from_str_loose() {
    assert_eq!(Role::from_str_loose("admin"), Some(Role::Admin));
    assert_eq!(Role::from_str_loose("OPERATOR"), Some(Role::Operator));
    assert_eq!(Role::from_str_loose("Support"), Some(Role::Support));
    assert_eq!(Role::from_str_loose("client"), Some(Role::Client));
    assert_eq!(Role::from_str_loose("bogus"), None);
}

#[test]
fn role_display() {
    assert_eq!(Role::Admin.to_string(), "admin");
    assert_eq!(Role::Client.to_string(), "client");
}

// --- Session lifecycle ---

#[tokio::test]
async fn create_user_and_login() {
    let db = Database::open_memory().unwrap();
    let user_id = session::create_user(&db, "testadmin", "secret123", Role::Admin)
        .await
        .unwrap();
    assert!(user_id > 0);

    let creds = session::LoginRequest {
        username: "testadmin".to_string(),
        password: "secret123".to_string(),
        totp_code: None,
    };

    let result = session::login(&db, &creds, Some("127.0.0.1"), None, 60)
        .await
        .unwrap();

    assert!(result.is_some(), "Login should succeed with correct password");
    let (sess, token) = result.unwrap();
    assert!(!token.is_empty());
    assert_eq!(sess.user_id, user_id);
}

#[tokio::test]
async fn login_wrong_password_returns_none() {
    let db = Database::open_memory().unwrap();
    session::create_user(&db, "user1", "correct", Role::Client)
        .await
        .unwrap();

    let creds = session::LoginRequest {
        username: "user1".to_string(),
        password: "wrong".to_string(),
        totp_code: None,
    };

    let result = session::login(&db, &creds, None, None, 60).await.unwrap();
    assert!(result.is_none(), "Login should fail with wrong password");
}

#[tokio::test]
async fn login_nonexistent_user_returns_none() {
    let db = Database::open_memory().unwrap();

    let creds = session::LoginRequest {
        username: "nobody".to_string(),
        password: "anything".to_string(),
        totp_code: None,
    };

    let result = session::login(&db, &creds, None, None, 60).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn validate_session_after_login() {
    let db = Database::open_memory().unwrap();
    session::create_user(&db, "alice", "pw123", Role::Operator)
        .await
        .unwrap();

    let creds = session::LoginRequest {
        username: "alice".to_string(),
        password: "pw123".to_string(),
        totp_code: None,
    };

    let (_, token) = session::login(&db, &creds, None, None, 60)
        .await
        .unwrap()
        .unwrap();

    let user = session::validate_session(&db, &token).await.unwrap();
    assert!(user.is_some());
    let user = user.unwrap();
    assert_eq!(user.username, "alice");
    assert_eq!(user.role, Role::Operator);
}

#[tokio::test]
async fn revoked_session_is_invalid() {
    let db = Database::open_memory().unwrap();
    session::create_user(&db, "bob", "pw", Role::Client)
        .await
        .unwrap();

    let creds = session::LoginRequest {
        username: "bob".to_string(),
        password: "pw".to_string(),
        totp_code: None,
    };

    let (_, token) = session::login(&db, &creds, None, None, 60)
        .await
        .unwrap()
        .unwrap();

    // Revoke (logout).
    session::revoke_session(&db, &token).await.unwrap();

    let user = session::validate_session(&db, &token).await.unwrap();
    assert!(user.is_none(), "Revoked session should not validate");
}

#[tokio::test]
async fn seed_admin_creates_default_user() {
    let db = Database::open_memory().unwrap();
    session::seed_admin_if_empty(&db).await.unwrap();

    let count: i64 = db
        .call(|conn| {
            conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
                .map_err(Into::into)
        })
        .await
        .unwrap();
    assert_eq!(count, 1, "Should create exactly one admin user");
}

#[tokio::test]
async fn seed_admin_is_idempotent() {
    let db = Database::open_memory().unwrap();
    session::seed_admin_if_empty(&db).await.unwrap();
    session::seed_admin_if_empty(&db).await.unwrap();

    let count: i64 = db
        .call(|conn| {
            conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
                .map_err(Into::into)
        })
        .await
        .unwrap();
    assert_eq!(count, 1, "Should not create duplicate admin user");
}
