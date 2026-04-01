//! Fail2Ban intrusion detection management API.

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::auth::{rbac::Permission, require_permission, AuthUser};
use crate::executor::command;
use crate::AppState;

#[derive(Serialize)]
pub struct Fail2BanStatus {
    pub running: bool,
    pub jails: Vec<JailInfo>,
}

#[derive(Serialize)]
pub struct JailInfo {
    pub name: String,
    pub enabled: bool,
    pub currently_banned: u32,
    pub total_banned: u32,
    pub banned_ips: Vec<String>,
}

#[derive(Deserialize)]
pub struct BanRequest {
    pub jail: String,
    pub ip: String,
}

#[derive(Deserialize)]
pub struct UnbanRequest {
    pub jail: String,
    pub ip: String,
}

/// GET /api/ids — fail2ban status and jail overview.
pub async fn get_status(
    State(_state): State<AppState>,
    AuthUser(user): AuthUser,
) -> Result<Json<Fail2BanStatus>, StatusCode> {
    require_permission(&user, Permission::ViewIds)?;

    // Check if fail2ban is running.
    let ping = command::exec_sudo("fail2ban-client", &["ping"])
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !ping.success {
        return Ok(Json(Fail2BanStatus {
            running: false,
            jails: vec![],
        }));
    }

    // Get jail list.
    let status = command::exec_sudo("fail2ban-client", &["status"])
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let jail_names = parse_jail_list(&status.stdout);
    let mut jails = Vec::new();

    for jail_name in &jail_names {
        let jail_status =
            command::exec_sudo("fail2ban-client", &["status", jail_name])
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        jails.push(parse_jail_status(jail_name, &jail_status.stdout));
    }

    Ok(Json(Fail2BanStatus {
        running: true,
        jails,
    }))
}

/// POST /api/ids/ban — manually ban an IP in a jail.
pub async fn ban_ip(
    State(_state): State<AppState>,
    AuthUser(user): AuthUser,
    Json(req): Json<BanRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_permission(&user, Permission::ManageIds)?;

    if !is_valid_jail_name(&req.jail) || !is_valid_ip(&req.ip) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let result =
        command::exec_sudo("fail2ban-client", &["set", &req.jail, "banip", &req.ip])
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "ok": result.success,
        "message": result.stdout.trim()
    })))
}

/// POST /api/ids/unban — unban an IP from a jail.
pub async fn unban_ip(
    State(_state): State<AppState>,
    AuthUser(user): AuthUser,
    Json(req): Json<UnbanRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_permission(&user, Permission::ManageIds)?;

    if !is_valid_jail_name(&req.jail) || !is_valid_ip(&req.ip) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let result =
        command::exec_sudo("fail2ban-client", &["set", &req.jail, "unbanip", &req.ip])
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "ok": result.success,
        "message": result.stdout.trim()
    })))
}

// --- Validation ---

fn is_valid_jail_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn is_valid_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

// --- Output parsing ---

fn parse_jail_list(output: &str) -> Vec<String> {
    for line in output.lines() {
        if line.contains("Jail list:") {
            if let Some(list_part) = line.split(':').nth(2) {
                return list_part
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }
    }
    Vec::new()
}

fn parse_jail_status(name: &str, output: &str) -> JailInfo {
    let mut currently_banned: u32 = 0;
    let mut total_banned: u32 = 0;
    let mut banned_ips = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("Currently banned:") {
            if let Some(num) = line.split(':').nth(1) {
                currently_banned = num.trim().parse().unwrap_or(0);
            }
        } else if line.starts_with("Total banned:") {
            if let Some(num) = line.split(':').nth(1) {
                total_banned = num.trim().parse().unwrap_or(0);
            }
        } else if line.starts_with("Banned IP list:") {
            if let Some(ips) = line.split(':').nth(1) {
                banned_ips = ips
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect();
            }
        }
    }

    JailInfo {
        name: name.to_string(),
        enabled: true,
        currently_banned,
        total_banned,
        banned_ips,
    }
}
