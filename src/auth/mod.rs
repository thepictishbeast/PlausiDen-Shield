//! Authentication and authorization module.
//!
//! Six-layer access control:
//!   1. RBAC  — role-based baseline
//!   2. ABAC  — attribute-based refinement
//!   3. PBAC  — probabilistic soft logic (future: NeuPSL)
//!   4. MAC   — mandatory sensitivity labels
//!   5. SoD   — separation of duties
//!   6. Contextual — step-up auth, break-glass, time-based

pub mod abac;
pub mod mac;
pub mod policy_engine;
pub mod rbac;
pub mod session;
pub mod sod;

use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};

use crate::AppState;

/// Axum extractor that validates the session cookie and provides the
/// authenticated user to handlers.
pub struct AuthUser(pub session::User);

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Extract session token from cookie header.
        let cookie_header = parts
            .headers
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let token = parse_cookie(cookie_header, "shield_session");
        let token = match token {
            Some(t) => t,
            None => return Err(StatusCode::UNAUTHORIZED),
        };

        match session::validate_session(&state.db, token).await {
            Ok(Some(user)) => Ok(AuthUser(user)),
            _ => Err(StatusCode::UNAUTHORIZED),
        }
    }
}

/// Parse a specific cookie value from a cookie header string.
pub fn parse_cookie<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    for pair in header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(name) {
            if let Some(value) = value.strip_prefix('=') {
                return Some(value);
            }
        }
    }
    None
}

/// Require a specific permission (use after AuthUser extraction).
pub fn require_permission(user: &session::User, perm: rbac::Permission) -> Result<(), StatusCode> {
    if user.role.has_permission(perm) {
        Ok(())
    } else {
        tracing::warn!(
            user = %user.username,
            role = %user.role,
            permission = ?perm,
            "Permission denied"
        );
        Err(StatusCode::FORBIDDEN)
    }
}
