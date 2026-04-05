//! Role-Based Access Control — Layer 1.
//!
//! Defines the role hierarchy and baseline permissions.
//! This is the foundation that higher layers refine.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::fmt;

/// User roles in descending privilege order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Operator,
    Support,
    Client,
}

impl Role {
    /// Numeric privilege level (higher = more privileged).
    pub fn level(&self) -> u8 {
        match self {
            Role::Admin => 100,
            Role::Operator => 75,
            Role::Support => 50,
            Role::Client => 25,
        }
    }

    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "admin" => Some(Role::Admin),
            "operator" => Some(Role::Operator),
            "support" => Some(Role::Support),
            "client" => Some(Role::Client),
            _ => None,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Admin => write!(f, "admin"),
            Role::Operator => write!(f, "operator"),
            Role::Support => write!(f, "support"),
            Role::Client => write!(f, "client"),
        }
    }
}

/// Granular permissions that RBAC maps to roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    // Dashboard
    ViewDashboard,

    // Security tools
    ManageFirewall,
    ViewFirewall,
    ManageIds,
    ViewIds,
    ManageAntivirus,
    ViewAntivirus,

    // Services
    ManageServices,
    ViewServices,

    // Files
    BrowseFiles,
    EditFiles,
    DeleteFiles,

    // Users & access control
    ManageUsers,
    ManageRoles,
    ManagePolicies,

    // Audit
    ViewAuditLog,

    // Tickets
    CreateTicket,
    ViewOwnTickets,
    ViewAllTickets,
    ManageTickets,

    // Integrations
    ManageIntegrations,
    ViewIntegrations,

    // Terminal
    WebTerminal,

    // Analytics
    ViewAnalytics,
    ExportData,
}

/// Static permission sets per role.
impl Role {
    pub fn permissions(&self) -> &'static [Permission] {
        match self {
            Role::Admin => &[
                Permission::ViewDashboard,
                Permission::ManageFirewall,
                Permission::ViewFirewall,
                Permission::ManageIds,
                Permission::ViewIds,
                Permission::ManageAntivirus,
                Permission::ViewAntivirus,
                Permission::ManageServices,
                Permission::ViewServices,
                Permission::BrowseFiles,
                Permission::EditFiles,
                Permission::DeleteFiles,
                Permission::ManageUsers,
                Permission::ManageRoles,
                Permission::ManagePolicies,
                Permission::ViewAuditLog,
                Permission::CreateTicket,
                Permission::ViewOwnTickets,
                Permission::ViewAllTickets,
                Permission::ManageTickets,
                Permission::ManageIntegrations,
                Permission::ViewIntegrations,
                Permission::WebTerminal,
                Permission::ViewAnalytics,
                Permission::ExportData,
            ],
            Role::Operator => &[
                Permission::ViewDashboard,
                Permission::ManageFirewall,
                Permission::ViewFirewall,
                Permission::ManageIds,
                Permission::ViewIds,
                Permission::ManageAntivirus,
                Permission::ViewAntivirus,
                Permission::ManageServices,
                Permission::ViewServices,
                Permission::BrowseFiles,
                Permission::ViewAuditLog,
                Permission::CreateTicket,
                Permission::ViewOwnTickets,
                Permission::ViewAllTickets,
                Permission::ViewIntegrations,
                Permission::ViewAnalytics,
            ],
            Role::Support => &[
                Permission::ViewDashboard,
                Permission::ViewFirewall,
                Permission::ViewIds,
                Permission::ViewAntivirus,
                Permission::ViewServices,
                Permission::CreateTicket,
                Permission::ViewOwnTickets,
                Permission::ViewAllTickets,
                Permission::ManageTickets,
                Permission::ViewIntegrations,
            ],
            Role::Client => &[
                Permission::ViewDashboard,
                Permission::CreateTicket,
                Permission::ViewOwnTickets,
            ],
        }
    }

    pub fn has_permission(&self, perm: Permission) -> bool {
        self.permissions().contains(&perm)
    }
}

/// RBAC evaluation result.
#[derive(Debug, Clone, Serialize)]
pub struct RbacDecision {
    pub allowed: bool,
    pub role: Role,
    pub permission: Permission,
    pub reason: String,
}

/// Evaluate RBAC: does the user's role grant the requested permission?
pub fn evaluate(role: Role, permission: Permission) -> RbacDecision {
    let allowed = role.has_permission(permission);
    let reason = if allowed {
        format!("Role '{}' includes permission '{:?}'", role, permission)
    } else {
        format!("Role '{}' does not include permission '{:?}'", role, permission)
    };
    RbacDecision {
        allowed,
        role,
        permission,
        reason,
    }
}
