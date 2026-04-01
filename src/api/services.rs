//! Systemd service management API.

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::auth::{rbac::Permission, require_permission, AuthUser};
use crate::executor::command;
use crate::AppState;

#[derive(Serialize)]
pub struct ServiceInfo {
    pub name: String,
    pub description: String,
    pub active_state: String,
    pub sub_state: String,
    pub enabled: bool,
    pub pid: Option<u32>,
    pub memory: Option<String>,
    pub uptime: Option<String>,
}

#[derive(Deserialize)]
pub struct ServiceAction {
    pub service: String,
    pub action: ServiceOp,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceOp {
    Start,
    Stop,
    Restart,
    Enable,
    Disable,
}

impl std::fmt::Display for ServiceOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceOp::Start => write!(f, "start"),
            ServiceOp::Stop => write!(f, "stop"),
            ServiceOp::Restart => write!(f, "restart"),
            ServiceOp::Enable => write!(f, "enable"),
            ServiceOp::Disable => write!(f, "disable"),
        }
    }
}

/// GET /api/services — list managed services.
pub async fn list_services(
    State(_state): State<AppState>,
    AuthUser(user): AuthUser,
) -> Result<Json<Vec<ServiceInfo>>, StatusCode> {
    require_permission(&user, Permission::ViewServices)?;

    let result = command::exec(
        "systemctl",
        &[
            "list-units",
            "--type=service",
            "--all",
            "--no-pager",
            "--no-legend",
            "--plain",
        ],
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let services = parse_service_list(&result.stdout);
    Ok(Json(services))
}

/// GET /api/services/:name — detailed status of a single service.
pub async fn get_service(
    State(_state): State<AppState>,
    AuthUser(user): AuthUser,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<Json<ServiceInfo>, StatusCode> {
    require_permission(&user, Permission::ViewServices)?;

    if !is_valid_service_name(&name) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let result = command::exec("systemctl", &["show", &name, "--no-pager"])
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let info = parse_systemctl_show(&name, &result.stdout);
    Ok(Json(info))
}

/// POST /api/services/action — start/stop/restart/enable/disable a service.
pub async fn service_action(
    State(_state): State<AppState>,
    AuthUser(user): AuthUser,
    Json(req): Json<ServiceAction>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_permission(&user, Permission::ManageServices)?;

    if !is_valid_service_name(&req.service) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let action_str = req.action.to_string();
    let result = command::exec_sudo("systemctl", &[&action_str, &req.service])
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "ok": result.success,
        "message": if result.success { "Operation completed" } else { result.stderr.trim() }
    })))
}

fn is_valid_service_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 256
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '@')
}

fn parse_service_list(output: &str) -> Vec<ServiceInfo> {
    let mut services = Vec::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let name = parts[0].trim_end_matches(".service").to_string();
            services.push(ServiceInfo {
                name,
                description: if parts.len() > 4 {
                    parts[4..].join(" ")
                } else {
                    String::new()
                },
                active_state: parts.get(2).unwrap_or(&"unknown").to_string(),
                sub_state: parts.get(3).unwrap_or(&"unknown").to_string(),
                enabled: false,
                pid: None,
                memory: None,
                uptime: None,
            });
        }
    }
    services
}

fn parse_systemctl_show(name: &str, output: &str) -> ServiceInfo {
    let mut info = ServiceInfo {
        name: name.to_string(),
        description: String::new(),
        active_state: "unknown".to_string(),
        sub_state: "unknown".to_string(),
        enabled: false,
        pid: None,
        memory: None,
        uptime: None,
    };

    for line in output.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match key {
                "Description" => info.description = value.to_string(),
                "ActiveState" => info.active_state = value.to_string(),
                "SubState" => info.sub_state = value.to_string(),
                "UnitFileState" => info.enabled = value == "enabled",
                "MainPID" => info.pid = value.parse().ok().filter(|&p: &u32| p > 0),
                "MemoryCurrent" => {
                    if let Ok(bytes) = value.parse::<u64>() {
                        info.memory = Some(format_bytes(bytes));
                    }
                }
                _ => {}
            }
        }
    }

    info
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
