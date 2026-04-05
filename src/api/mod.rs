//! API router — assembles all endpoint groups.

pub mod antivirus;
pub mod files;
pub mod firewall;
pub mod ids;
pub mod services;
pub mod system;

use axum::{
    extract::State,
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};

use crate::auth::{
    rbac::Permission,
    require_permission,
    session::{self, LoginRequest},
    AuthUser,
};
use crate::AppState;

/// Build the full API router.
pub fn router() -> Router<AppState> {
    Router::new()
        // Auth
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/me", get(me))
        // System
        .route("/api/system", get(system::get_system_overview))
        // Firewall
        .route("/api/firewall", get(firewall::get_status))
        .route("/api/firewall/rules", post(firewall::add_rule))
        .route("/api/firewall/rules/:number", delete(firewall::delete_rule))
        .route("/api/firewall/enable", post(firewall::enable))
        .route("/api/firewall/disable", post(firewall::disable))
        // IDS (fail2ban)
        .route("/api/ids", get(ids::get_status))
        .route("/api/ids/ban", post(ids::ban_ip))
        .route("/api/ids/unban", post(ids::unban_ip))
        // Services
        .route("/api/services", get(services::list_services))
        .route("/api/services/:name", get(services::get_service))
        .route("/api/services/action", post(services::service_action))
        // Files
        .route("/api/files", get(files::browse))
        .route("/api/files/read", get(files::read_file))
        // Antivirus
        .route("/api/antivirus", get(antivirus::get_status))
        .route("/api/antivirus/scan", post(antivirus::scan))
        .route("/api/antivirus/update", post(antivirus::update_definitions))
        // Tickets
        .route("/api/tickets", get(list_tickets).post(create_ticket))
        .route("/api/tickets/:id", get(get_ticket).patch(update_ticket))
        .route("/api/tickets/:id/comments", post(add_ticket_comment))
        // Analytics
        .route("/api/analytics/metrics", get(get_metrics))
        .route("/api/analytics/audit", get(get_audit_log))
        // Integrations
        .route("/api/integrations", get(list_integrations))
        .route("/api/integrations/health", get(integration_health))
}

// --- Auth endpoints ---

async fn login(
    State(state): State<AppState>,
    Json(creds): Json<LoginRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let result = session::login(
        &state.db,
        &creds,
        None, // IP extracted from request in production
        None,
        state.config.auth.session_timeout_minutes,
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match result {
        Some((sess, token)) => Ok(Json(serde_json::json!({
            "ok": true,
            "session_id": sess.id,
            "token": token,
            "expires_at": sess.expires_at,
        }))),
        None => Err(StatusCode::UNAUTHORIZED),
    }
}

async fn logout(
    State(state): State<AppState>,
    AuthUser(_user): AuthUser,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let cookie_header = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if let Some(token) = crate::auth::parse_cookie(cookie_header, "shield_session") {
        session::revoke_session(&state.db, token)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn me(AuthUser(user): AuthUser) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "email": user.email,
        "totp_enabled": user.totp_enabled,
    }))
}

// --- Ticket endpoints ---

async fn list_tickets(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
) -> Result<Json<Vec<crate::tickets::Ticket>>, StatusCode> {
    require_permission(&user, Permission::ViewAllTickets)?;
    let tickets = crate::tickets::list(&state.db, None)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(tickets))
}

async fn create_ticket(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Json(req): Json<crate::tickets::CreateTicket>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_permission(&user, Permission::CreateTicket)?;
    let id = crate::tickets::create(&state.db, user.id, &req)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({ "ok": true, "id": id })))
}

async fn get_ticket(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_permission(&user, Permission::ViewAllTickets)?;
    let ticket = crate::tickets::get(&state.db, id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    match ticket {
        Some(t) => {
            let comments = crate::tickets::get_comments(&state.db, id)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            Ok(Json(serde_json::json!({
                "ticket": t,
                "comments": comments,
            })))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn update_ticket(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    axum::extract::Path(id): axum::extract::Path<i64>,
    Json(req): Json<crate::tickets::UpdateTicket>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_permission(&user, Permission::ManageTickets)?;
    crate::tickets::update(&state.db, id, &req)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn add_ticket_comment(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    axum::extract::Path(id): axum::extract::Path<i64>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_permission(&user, Permission::CreateTicket)?;
    let text = body["body"].as_str().unwrap_or("");
    if text.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let comment_id = crate::tickets::add_comment(&state.db, id, user.id, text)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({ "ok": true, "id": comment_id })))
}

// --- Analytics endpoints ---

#[derive(serde::Deserialize)]
struct MetricsQuery {
    metric_type: String,
    metric_name: String,
    limit: Option<u32>,
}

async fn get_metrics(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    axum::extract::Query(query): axum::extract::Query<MetricsQuery>,
) -> Result<Json<Vec<crate::analytics::MetricPoint>>, StatusCode> {
    require_permission(&user, Permission::ViewAnalytics)?;
    let points = crate::analytics::get_metrics(
        &state.db,
        &query.metric_type,
        &query.metric_name,
        query.limit.unwrap_or(100),
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(points))
}

async fn get_audit_log(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
) -> Result<Json<Vec<crate::analytics::AuditEntry>>, StatusCode> {
    require_permission(&user, Permission::ViewAuditLog)?;
    let entries = crate::analytics::get_audit_log(&state.db, 200)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(entries))
}

// --- Integration endpoints ---

async fn list_integrations(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
) -> Result<Json<Vec<String>>, StatusCode> {
    require_permission(&user, Permission::ViewIntegrations)?;
    let names = state.integrations.list().await;
    Ok(Json(names))
}

async fn integration_health(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
) -> Result<Json<Vec<crate::integrations::HealthReport>>, StatusCode> {
    require_permission(&user, Permission::ViewIntegrations)?;
    let reports = state.integrations.health_check_all().await;
    Ok(Json(reports))
}
