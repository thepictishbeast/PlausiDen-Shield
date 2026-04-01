//! Mandatory Access Control — Layer 4.
//!
//! Non-overridable security floor. Users have a clearance level;
//! resources have a sensitivity label. Access is denied if the user's
//! clearance is below the resource's sensitivity.
//!
//! Labels follow a strict ordering:
//!   Public < Internal < Confidential < Restricted

use serde::{Deserialize, Serialize};
use std::fmt;

/// Security classification labels — strictly ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityLabel {
    Public = 0,
    Internal = 1,
    Confidential = 2,
    Restricted = 3,
}

impl SecurityLabel {
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "public" => Some(SecurityLabel::Public),
            "internal" => Some(SecurityLabel::Internal),
            "confidential" => Some(SecurityLabel::Confidential),
            "restricted" => Some(SecurityLabel::Restricted),
            _ => None,
        }
    }
}

impl fmt::Display for SecurityLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityLabel::Public => write!(f, "public"),
            SecurityLabel::Internal => write!(f, "internal"),
            SecurityLabel::Confidential => write!(f, "confidential"),
            SecurityLabel::Restricted => write!(f, "restricted"),
        }
    }
}

/// MAC evaluation result.
#[derive(Debug, Clone, Serialize)]
pub struct MacDecision {
    pub allowed: bool,
    pub user_clearance: SecurityLabel,
    pub resource_label: SecurityLabel,
    pub reason: String,
}

/// Evaluate MAC: user clearance must be >= resource sensitivity.
///
/// This is a hard floor — no higher layer can override a MAC denial.
pub fn evaluate(user_clearance: SecurityLabel, resource_label: SecurityLabel) -> MacDecision {
    let allowed = user_clearance >= resource_label;
    let reason = if allowed {
        format!(
            "User clearance '{}' meets or exceeds resource label '{}'",
            user_clearance, resource_label
        )
    } else {
        format!(
            "User clearance '{}' is below resource label '{}' — MAC hard deny",
            user_clearance, resource_label
        )
    };

    MacDecision {
        allowed,
        user_clearance,
        resource_label,
        reason,
    }
}
