//! Separation of Duties — Layer 5.
//!
//! Prevents the same user from performing conflicting actions.
//! Example: the user who creates a firewall rule cannot also approve it
//! in a change-management workflow.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A separation-of-duties constraint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SodConstraint {
    pub name: String,
    /// Set of actions that conflict — no single user may perform more than
    /// `max_per_user` of these on the same resource.
    pub conflicting_actions: HashSet<String>,
    /// Maximum number of the conflicting actions a single user may perform.
    /// Default is 1 (any two conflict).
    #[serde(default = "default_max")]
    pub max_per_user: usize,
}

fn default_max() -> usize {
    1
}

/// SoD evaluation result.
#[derive(Debug, Clone, Serialize)]
pub struct SodDecision {
    pub allowed: bool,
    pub violated_constraints: Vec<String>,
    pub reason: String,
}

/// Evaluate SoD constraints.
///
/// `prior_actions` is the set of actions the requesting user has already
/// performed on the target resource (loaded from audit log).
pub fn evaluate(
    constraints: &[SodConstraint],
    requested_action: &str,
    prior_actions: &HashSet<String>,
) -> SodDecision {
    let mut violations: Vec<String> = Vec::new();

    for constraint in constraints {
        if !constraint.conflicting_actions.contains(requested_action) {
            continue;
        }

        // Count how many of the conflicting actions this user has already done.
        let prior_count = prior_actions
            .iter()
            .filter(|a| constraint.conflicting_actions.contains(a.as_str()))
            .count();

        // The requested action would push them over the limit.
        if prior_count >= constraint.max_per_user {
            violations.push(constraint.name.clone());
        }
    }

    if violations.is_empty() {
        SodDecision {
            allowed: true,
            violated_constraints: vec![],
            reason: "No SoD constraints violated".to_string(),
        }
    } else {
        let names = violations.join(", ");
        SodDecision {
            allowed: false,
            violated_constraints: violations,
            reason: format!("SoD violation: {}", names),
        }
    }
}

/// Parse SoD constraints from a JSON string.
pub fn parse_constraints(json: &str) -> anyhow::Result<Vec<SodConstraint>> {
    let constraints: Vec<SodConstraint> = serde_json::from_str(json)?;
    Ok(constraints)
}
