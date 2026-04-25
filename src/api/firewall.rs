//! UFW firewall management API.
//!
//! All UFW commands go through executor::command — no shell interpolation.

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::auth::{rbac::Permission, require_permission, AuthUser};
use crate::executor::command;
use crate::AppState;

#[derive(Serialize)]
pub struct FirewallStatus {
    pub active: bool,
    pub default_incoming: String,
    pub default_outgoing: String,
    pub rules: Vec<FirewallRule>,
}

#[derive(Serialize)]
pub struct FirewallRule {
    pub number: usize,
    pub to: String,
    pub action: String,
    pub from: String,
    pub comment: Option<String>,
    pub raw: String,
}

#[derive(Deserialize)]
pub struct AddRuleRequest {
    pub action: RuleAction,
    pub direction: Option<RuleDirection>,
    pub port: Option<String>,
    pub proto: Option<String>,
    pub from_addr: Option<String>,
    pub to_addr: Option<String>,
    pub comment: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Deny,
    Reject,
    Limit,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleDirection {
    In,
    Out,
}

impl std::fmt::Display for RuleAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleAction::Allow => write!(f, "allow"),
            RuleAction::Deny => write!(f, "deny"),
            RuleAction::Reject => write!(f, "reject"),
            RuleAction::Limit => write!(f, "limit"),
        }
    }
}

/// GET /api/firewall — current UFW status and rules.
pub async fn get_status(
    State(_state): State<AppState>,
    AuthUser(user): AuthUser,
) -> Result<Json<FirewallStatus>, StatusCode> {
    require_permission(&user, Permission::ViewFirewall)?;

    let result = command::exec_sudo("ufw", &["status", "numbered"])
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let status = parse_ufw_status(&result.stdout);
    Ok(Json(status))
}

/// POST /api/firewall/rules — add a new UFW rule.
pub async fn add_rule(
    State(_state): State<AppState>,
    AuthUser(user): AuthUser,
    Json(req): Json<AddRuleRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_permission(&user, Permission::ManageFirewall)?;

    let mut args: Vec<String> = Vec::new();
    args.push(req.action.to_string());

    if let Some(dir) = &req.direction {
        match dir {
            RuleDirection::In => args.push("in".to_string()),
            RuleDirection::Out => args.push("out".to_string()),
        }
    }

    if let Some(from) = &req.from_addr {
        // Validate: must be an IP address or CIDR, not shell metacharacters.
        if !is_valid_address(from) {
            return Err(StatusCode::BAD_REQUEST);
        }
        args.push("from".to_string());
        args.push(from.clone());
    }

    if let Some(to) = &req.to_addr {
        if !is_valid_address(to) {
            return Err(StatusCode::BAD_REQUEST);
        }
        args.push("to".to_string());
        args.push(to.clone());
    }

    if let Some(port) = &req.port {
        // Validate port: digits, commas, colons, slashes only.
        if !is_valid_port_spec(port) {
            return Err(StatusCode::BAD_REQUEST);
        }
        args.push("port".to_string());
        args.push(port.clone());
    }

    if let Some(proto) = &req.proto {
        let proto_lower = proto.to_lowercase();
        if proto_lower != "tcp" && proto_lower != "udp" {
            return Err(StatusCode::BAD_REQUEST);
        }
        args.push("proto".to_string());
        args.push(proto_lower);
    }

    if let Some(comment) = &req.comment {
        args.push("comment".to_string());
        args.push(comment.clone());
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = command::exec_sudo("ufw", &arg_refs)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.success {
        Ok(Json(
            serde_json::json!({ "ok": true, "message": result.stdout.trim() }),
        ))
    } else {
        Ok(Json(
            serde_json::json!({ "ok": false, "error": result.stderr.trim() }),
        ))
    }
}

/// DELETE /api/firewall/rules/:number — delete a rule by number.
pub async fn delete_rule(
    State(_state): State<AppState>,
    AuthUser(user): AuthUser,
    axum::extract::Path(number): axum::extract::Path<u32>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_permission(&user, Permission::ManageFirewall)?;

    let num_str = number.to_string();
    let result = command::exec_sudo("ufw", &["--force", "delete", &num_str])
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.success {
        Ok(Json(serde_json::json!({ "ok": true })))
    } else {
        Ok(Json(
            serde_json::json!({ "ok": false, "error": result.stderr.trim() }),
        ))
    }
}

/// POST /api/firewall/enable — enable UFW.
pub async fn enable(
    State(_state): State<AppState>,
    AuthUser(user): AuthUser,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_permission(&user, Permission::ManageFirewall)?;

    let result = command::exec_sudo("ufw", &["--force", "enable"])
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({ "ok": result.success })))
}

/// POST /api/firewall/disable — disable UFW.
pub async fn disable(
    State(_state): State<AppState>,
    AuthUser(user): AuthUser,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_permission(&user, Permission::ManageFirewall)?;

    let result = command::exec_sudo("ufw", &["--force", "disable"])
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({ "ok": result.success })))
}

// --- Input validation helpers ---

fn is_valid_address(s: &str) -> bool {
    // Allow IPv4, IPv6, CIDR notation, and "any".
    let s = s.trim();
    if s == "any" || s == "Anywhere" {
        return true;
    }
    // Simple character allowlist: digits, dots, colons, slashes, hex letters.
    s.chars().all(|c| {
        c.is_ascii_digit()
            || c == '.'
            || c == ':'
            || c == '/'
            || ('a'..='f').contains(&c)
            || ('A'..='F').contains(&c)
    })
}

fn is_valid_port_spec(s: &str) -> bool {
    // Allow digits, commas (ranges), colons (port ranges), slashes (proto).
    s.chars()
        .all(|c| c.is_ascii_digit() || c == ',' || c == ':' || c == '/')
}

// --- UFW output parsing ---

fn parse_ufw_status(output: &str) -> FirewallStatus {
    let lines: Vec<&str> = output.lines().collect();
    let active = lines.first().map(|l| l.contains("active")).unwrap_or(false)
        && !lines
            .first()
            .map(|l| l.contains("inactive"))
            .unwrap_or(true);

    let mut rules = Vec::new();
    let mut in_rules = false;

    for line in &lines {
        if line.starts_with("---") {
            in_rules = true;
            continue;
        }
        if !in_rules || line.trim().is_empty() {
            continue;
        }

        // Parse numbered rule lines like: "[ 1] 22/tcp  ALLOW IN  Anywhere"
        if let Some(rule) = parse_rule_line(line, rules.len() + 1) {
            rules.push(rule);
        }
    }

    FirewallStatus {
        active,
        default_incoming: "deny".to_string(),
        default_outgoing: "allow".to_string(),
        rules,
    }
}

fn parse_rule_line(line: &str, fallback_num: usize) -> Option<FirewallRule> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Try to extract number from "[ N]" prefix.
    let (num, rest) = if trimmed.starts_with('[') {
        if let Some(bracket_end) = trimmed.find(']') {
            let num_str = trimmed[1..bracket_end].trim();
            let num: usize = num_str.parse().unwrap_or(fallback_num);
            (num, trimmed[bracket_end + 1..].trim())
        } else {
            (fallback_num, trimmed)
        }
    } else {
        (fallback_num, trimmed)
    };

    // Split on ALLOW/DENY/REJECT/LIMIT.
    let (to_part, action, from_part) = if let Some(pos) = rest.find("ALLOW") {
        (&rest[..pos], "ALLOW", &rest[pos + 5..])
    } else if let Some(pos) = rest.find("DENY") {
        (&rest[..pos], "DENY", &rest[pos + 4..])
    } else if let Some(pos) = rest.find("REJECT") {
        (&rest[..pos], "REJECT", &rest[pos + 6..])
    } else if let Some(pos) = rest.find("LIMIT") {
        (&rest[..pos], "LIMIT", &rest[pos + 5..])
    } else {
        return Some(FirewallRule {
            number: num,
            to: String::new(),
            action: String::new(),
            from: String::new(),
            comment: None,
            raw: line.to_string(),
        });
    };

    let from_clean = from_part
        .trim()
        .trim_start_matches("IN")
        .trim_start_matches("OUT")
        .trim();

    Some(FirewallRule {
        number: num,
        to: to_part.trim().to_string(),
        action: action.to_string(),
        from: from_clean.to_string(),
        comment: None,
        raw: line.to_string(),
    })
}
