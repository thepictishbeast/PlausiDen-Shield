//! ClamAV antivirus management API.

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::auth::{rbac::Permission, require_permission, AuthUser};
use crate::executor::command;
use crate::AppState;

#[derive(Serialize)]
pub struct ClamAvStatus {
    pub daemon_running: bool,
    pub version: Option<String>,
    pub database_version: Option<String>,
    pub last_update: Option<String>,
    pub known_viruses: Option<u64>,
}

#[derive(Serialize)]
pub struct ScanResult {
    pub path: String,
    pub infected_files: u32,
    pub scanned_files: u32,
    pub threats: Vec<ThreatInfo>,
    pub duration_seconds: f64,
}

#[derive(Serialize)]
pub struct ThreatInfo {
    pub file: String,
    pub threat_name: String,
}

#[derive(Deserialize)]
pub struct ScanRequest {
    pub path: String,
    pub recursive: Option<bool>,
}

/// GET /api/antivirus — ClamAV daemon status.
pub async fn get_status(
    State(_state): State<AppState>,
    AuthUser(user): AuthUser,
) -> Result<Json<ClamAvStatus>, StatusCode> {
    require_permission(&user, Permission::ViewAntivirus)?;

    // Check if clamd is running.
    let ping = command::exec("clamdscan", &["--ping"])
        .await;

    let daemon_running = ping.as_ref().map(|r| r.success).unwrap_or(false);

    // Get version info.
    let version_result = command::exec("clamdscan", &["--version"]).await;
    let version = version_result.ok().map(|r| r.stdout.trim().to_string());

    Ok(Json(ClamAvStatus {
        daemon_running,
        version,
        database_version: None,
        last_update: None,
        known_viruses: None,
    }))
}

/// POST /api/antivirus/scan — trigger a scan on a path.
pub async fn scan(
    State(_state): State<AppState>,
    AuthUser(user): AuthUser,
    Json(req): Json<ScanRequest>,
) -> Result<Json<ScanResult>, StatusCode> {
    require_permission(&user, Permission::ManageAntivirus)?;

    // Validate path — must exist and not be in forbidden locations.
    let path = std::path::PathBuf::from(&req.path);
    let canonical = path.canonicalize().map_err(|_| StatusCode::BAD_REQUEST)?;

    // Block scanning /proc, /sys, /dev.
    let path_str = canonical.to_string_lossy();
    if path_str.starts_with("/proc") || path_str.starts_with("/sys") || path_str.starts_with("/dev")
    {
        return Err(StatusCode::FORBIDDEN);
    }

    let mut args = vec!["--infected", "--no-summary"];
    if req.recursive.unwrap_or(true) {
        args.push("-r");
    }
    let scan_path = canonical.to_string_lossy().to_string();
    args.push(&scan_path);

    let start = std::time::Instant::now();
    let result = command::exec("clamdscan", &args)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let duration = start.elapsed().as_secs_f64();

    let threats = parse_clam_output(&result.stdout);
    let infected_count = threats.len() as u32;

    Ok(Json(ScanResult {
        path: scan_path,
        infected_files: infected_count,
        scanned_files: 0, // clamdscan doesn't always report this with --no-summary
        threats,
        duration_seconds: duration,
    }))
}

/// POST /api/antivirus/update — update virus definitions.
pub async fn update_definitions(
    State(_state): State<AppState>,
    AuthUser(user): AuthUser,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_permission(&user, Permission::ManageAntivirus)?;

    let result = command::exec_sudo("freshclam", &[])
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "ok": result.success,
        "output": result.stdout.trim(),
    })))
}

fn parse_clam_output(output: &str) -> Vec<ThreatInfo> {
    let mut threats = Vec::new();
    for line in output.lines() {
        // ClamAV output: "/path/to/file: ThreatName FOUND"
        if line.ends_with("FOUND") {
            if let Some((file_part, rest)) = line.rsplit_once(": ") {
                let threat_name = rest.trim_end_matches(" FOUND").trim().to_string();
                threats.push(ThreatInfo {
                    file: file_part.to_string(),
                    threat_name,
                });
            }
        }
    }
    threats
}
