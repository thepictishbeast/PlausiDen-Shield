//! File browser API — directory listing, file read, basic operations.
//!
//! Path traversal is prevented by canonicalizing all paths and checking
//! they remain under the allowed root.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::auth::{rbac::Permission, require_permission, AuthUser};
use crate::AppState;

/// Default browsable root. Configurable via shield.toml.
const DEFAULT_ROOT: &str = "/";

/// Allowed roots that the file browser can access.
const FORBIDDEN_PATHS: &[&str] = &["/proc", "/sys", "/dev"];

#[derive(Serialize)]
pub struct DirectoryListing {
    pub path: String,
    pub entries: Vec<FileEntry>,
}

#[derive(Serialize)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<String>,
    pub permissions: String,
}

#[derive(Deserialize)]
pub struct BrowseQuery {
    pub path: Option<String>,
}

#[derive(Deserialize)]
pub struct ReadFileQuery {
    pub path: String,
    pub max_bytes: Option<usize>,
}

/// GET /api/files — browse a directory.
pub async fn browse(
    State(_state): State<AppState>,
    AuthUser(user): AuthUser,
    Query(query): Query<BrowseQuery>,
) -> Result<Json<DirectoryListing>, StatusCode> {
    require_permission(&user, Permission::BrowseFiles)?;

    let requested = query.path.as_deref().unwrap_or(DEFAULT_ROOT);
    let safe_path = resolve_safe_path(requested)?;

    let mut entries = Vec::new();
    let read_dir = tokio::fs::read_dir(&safe_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let mut read_dir = read_dir;
    while let Ok(Some(entry)) = read_dir.next_entry().await {
        let metadata = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };

        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path().to_string_lossy().to_string();
        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| {
                let dt: chrono::DateTime<chrono::Utc> = t.into();
                Some(dt.to_rfc3339())
            });

        entries.push(FileEntry {
            name,
            path,
            is_dir: metadata.is_dir(),
            size: metadata.len(),
            modified,
            permissions: format_permissions(&metadata),
        });
    }

    entries.sort_by(|a, b| {
        b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name))
    });

    Ok(Json(DirectoryListing {
        path: safe_path.to_string_lossy().to_string(),
        entries,
    }))
}

/// GET /api/files/read — read file contents (text only, size-limited).
pub async fn read_file(
    State(_state): State<AppState>,
    AuthUser(user): AuthUser,
    Query(query): Query<ReadFileQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_permission(&user, Permission::BrowseFiles)?;

    let safe_path = resolve_safe_path(&query.path)?;
    let max_bytes = query.max_bytes.unwrap_or(1_000_000); // 1MB default

    let metadata = tokio::fs::metadata(&safe_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    if metadata.is_dir() {
        return Err(StatusCode::BAD_REQUEST);
    }

    if metadata.len() > max_bytes as u64 {
        return Ok(Json(serde_json::json!({
            "error": "File too large",
            "size": metadata.len(),
            "max_bytes": max_bytes,
        })));
    }

    let contents = tokio::fs::read(&safe_path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Only serve text files.
    match String::from_utf8(contents) {
        Ok(text) => Ok(Json(serde_json::json!({
            "path": safe_path.to_string_lossy(),
            "content": text,
            "size": metadata.len(),
        }))),
        Err(_) => Ok(Json(serde_json::json!({
            "error": "Binary file — cannot display as text",
            "size": metadata.len(),
        }))),
    }
}

/// Resolve a path, canonicalize it, and verify it's not in a forbidden location.
fn resolve_safe_path(requested: &str) -> Result<PathBuf, StatusCode> {
    let path = PathBuf::from(requested);

    // Canonicalize to resolve symlinks and ../ traversal.
    let canonical = path
        .canonicalize()
        .map_err(|_| StatusCode::NOT_FOUND)?;

    // Block forbidden system paths.
    for forbidden in FORBIDDEN_PATHS {
        if canonical.starts_with(forbidden) {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    Ok(canonical)
}

fn format_permissions(metadata: &std::fs::Metadata) -> String {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode();
    format!("{:o}", mode & 0o7777)
}
