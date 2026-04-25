//! Session management — Layer 0 (authentication gate).
//!
//! Sessions are stored in SQLite. Tokens are SHA-256 hashed before storage.
//! Session cookies are httpOnly + Secure + SameSite=Strict.
#![allow(dead_code)]

use anyhow::{Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::rbac::Role;
use crate::db::Database;

/// A user record from the database.
#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: Role,
    pub email: Option<String>,
    pub totp_enabled: bool,
    pub security_label: String,
    pub attributes: serde_json::Value,
    pub is_active: bool,
    pub created_at: String,
    pub last_login_at: Option<String>,
}

/// An active session.
#[derive(Debug, Clone, Serialize)]
pub struct Session {
    pub id: String,
    pub user_id: i64,
    pub ip_address: Option<String>,
    pub created_at: String,
    pub expires_at: String,
}

/// Login credentials.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub totp_code: Option<String>,
}

/// Hash a password with argon2.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Password hashing failed: {}", e))?;
    Ok(hash.to_string())
}

/// Verify a password against a stored hash.
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| anyhow::anyhow!("Invalid password hash format: {}", e))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// SHA-256 hash of a session token (for storage).
fn hash_token(token: &str) -> String {
    use std::fmt::Write;
    let digest = <sha2::Sha256 as sha2::Digest>::digest(token.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        let _ = write!(hex, "{:02x}", byte);
    }
    hex
}

/// Create a new user in the database.
pub async fn create_user(db: &Database, username: &str, password: &str, role: Role) -> Result<i64> {
    let pw_hash = hash_password(password)?;
    let role_str = role.to_string();
    let uname = username.to_string();

    db.call(move |conn| {
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?1, ?2, ?3)",
            rusqlite::params![uname, pw_hash, role_str],
        )
        .context("Failed to create user")?;
        Ok(conn.last_insert_rowid())
    })
    .await
}

/// Authenticate a user and create a session.
pub async fn login(
    db: &Database,
    creds: &LoginRequest,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    session_timeout_minutes: u64,
) -> Result<Option<(Session, String)>> {
    let username = creds.username.clone();
    let password = creds.password.clone();
    let ip = ip_address.map(|s| s.to_string());
    let ua = user_agent.map(|s| s.to_string());

    db.call(move |conn| {
        // Look up user.
        let user: Option<(i64, String, String, bool)> = conn
            .query_row(
                "SELECT id, password_hash, role, is_active FROM users WHERE username = ?1",
                rusqlite::params![username],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, bool>(3)?,
                    ))
                },
            )
            .optional()
            .context("User lookup failed")?;

        let (user_id, stored_hash, _role_str, is_active) = match user {
            Some(u) => u,
            None => return Ok(None),
        };

        if !is_active {
            return Ok(None);
        }

        // Verify password.
        let valid = verify_password(&password, &stored_hash)?;
        if !valid {
            return Ok(None);
        }

        // Create session.
        let session_id = Uuid::new_v4().to_string();
        let token = Uuid::new_v4().to_string();
        let token_hash = hash_token(&token);
        let now = Utc::now();
        let expires = now + Duration::minutes(session_timeout_minutes as i64);

        conn.execute(
            "INSERT INTO sessions (id, user_id, token_hash, ip_address, user_agent, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                session_id,
                user_id,
                token_hash,
                ip.as_deref(),
                ua.as_deref(),
                expires.to_rfc3339(),
            ],
        )
        .context("Session creation failed")?;

        // Update last login.
        conn.execute(
            "UPDATE users SET last_login_at = ?1 WHERE id = ?2",
            rusqlite::params![now.to_rfc3339(), user_id],
        )?;

        let session = Session {
            id: session_id,
            user_id,
            ip_address: ip,
            created_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
        };

        Ok(Some((session, token)))
    })
    .await
}

/// Validate a session token and return the associated user.
pub async fn validate_session(db: &Database, token: &str) -> Result<Option<User>> {
    let token_hash = hash_token(token);

    db.call(move |conn| {
        let result: Option<(i64, String)> = conn
            .query_row(
                "SELECT user_id, expires_at FROM sessions \
                 WHERE token_hash = ?1 AND is_revoked = 0",
                rusqlite::params![token_hash],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .context("Session lookup failed")?;

        let (user_id, expires_at) = match result {
            Some(r) => r,
            None => return Ok(None),
        };

        // Check expiry.
        if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(&expires_at) {
            if exp < Utc::now() {
                return Ok(None);
            }
        }

        // Load user.
        let user = conn
            .query_row(
                "SELECT id, username, password_hash, role, email, totp_enabled, \
                 security_label, attributes, is_active, created_at, last_login_at \
                 FROM users WHERE id = ?1",
                rusqlite::params![user_id],
                |row| {
                    let role_str: String = row.get(3)?;
                    let attrs_str: String = row.get(7)?;
                    Ok(User {
                        id: row.get(0)?,
                        username: row.get(1)?,
                        password_hash: row.get(2)?,
                        role: Role::from_str_loose(&role_str).unwrap_or(Role::Client),
                        email: row.get(4)?,
                        totp_enabled: row.get(5)?,
                        security_label: row.get(6)?,
                        attributes: serde_json::from_str(&attrs_str).unwrap_or_default(),
                        is_active: row.get(8)?,
                        created_at: row.get(9)?,
                        last_login_at: row.get(10)?,
                    })
                },
            )
            .optional()
            .context("User lookup by ID failed")?;

        match user {
            Some(u) if u.is_active => Ok(Some(u)),
            _ => Ok(None),
        }
    })
    .await
}

/// Revoke a session (logout).
pub async fn revoke_session(db: &Database, token: &str) -> Result<()> {
    let token_hash = hash_token(token);
    db.call(move |conn| {
        conn.execute(
            "UPDATE sessions SET is_revoked = 1 WHERE token_hash = ?1",
            rusqlite::params![token_hash],
        )?;
        Ok(())
    })
    .await
}

/// Seed the default admin user if no users exist.
pub async fn seed_admin_if_empty(db: &Database) -> Result<()> {
    let count: i64 = db
        .call(|conn| {
            conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
                .context("Failed to count users")
        })
        .await?;

    if count == 0 {
        let default_pw = std::env::var("SHIELD_ADMIN_PASSWORD").unwrap_or_else(|_| {
            let pw = Uuid::new_v4().to_string();
            tracing::warn!(
                "No SHIELD_ADMIN_PASSWORD set. Generated random admin password: {}",
                pw
            );
            pw
        });

        create_user(db, "admin", &default_pw, Role::Admin).await?;
        tracing::info!("Default admin user created");
    }

    Ok(())
}

// Re-export rusqlite's OptionalExtension for use in this module.
use rusqlite::OptionalExtension;
