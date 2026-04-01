//! Attribute-Based Access Control — Layer 2.
//!
//! Evaluates access based on attributes of the user, resource, action,
//! and environment. Policies are loaded from the database or policy files.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Attributes attached to an access request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessAttributes {
    /// User attributes (department, clearance, location, etc.).
    pub user: HashMap<String, serde_json::Value>,
    /// Resource attributes (owner, sensitivity, type, etc.).
    pub resource: HashMap<String, serde_json::Value>,
    /// Action being performed.
    pub action: String,
    /// Environment attributes (time of day, IP range, etc.).
    pub environment: HashMap<String, serde_json::Value>,
}

/// An ABAC policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbacRule {
    pub name: String,
    /// Conditions that must ALL be true for this rule to apply.
    pub conditions: Vec<AbacCondition>,
    /// Effect when conditions match.
    pub effect: PolicyEffect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbacCondition {
    /// Which attribute set to check: "user", "resource", "environment".
    pub target: String,
    /// Attribute key.
    pub key: String,
    /// Comparison operator.
    pub operator: ConditionOp,
    /// Expected value.
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOp {
    Equals,
    NotEquals,
    Contains,
    In,
    GreaterThan,
    LessThan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyEffect {
    Allow,
    Deny,
}

/// Result of ABAC evaluation.
#[derive(Debug, Clone, Serialize)]
pub struct AbacDecision {
    pub allowed: bool,
    pub matched_rules: Vec<String>,
    pub reason: String,
}

/// Evaluate ABAC rules against the given attributes.
///
/// Default-deny: if no rule explicitly allows, access is denied.
/// Any deny rule takes precedence over allow rules.
pub fn evaluate(rules: &[AbacRule], attrs: &AccessAttributes) -> AbacDecision {
    let mut matched_allow: Vec<String> = Vec::new();
    let mut matched_deny: Vec<String> = Vec::new();

    for rule in rules {
        if rule_matches(rule, attrs) {
            match rule.effect {
                PolicyEffect::Allow => matched_allow.push(rule.name.clone()),
                PolicyEffect::Deny => matched_deny.push(rule.name.clone()),
            }
        }
    }

    if !matched_deny.is_empty() {
        let names = matched_deny.join(", ");
        return AbacDecision {
            allowed: false,
            matched_rules: matched_deny,
            reason: format!("Denied by ABAC rules: {}", names),
        };
    }

    if !matched_allow.is_empty() {
        let names = matched_allow.join(", ");
        return AbacDecision {
            allowed: true,
            matched_rules: matched_allow,
            reason: format!("Allowed by ABAC rules: {}", names),
        };
    }

    AbacDecision {
        allowed: false,
        matched_rules: vec![],
        reason: "No ABAC rule matched; default deny".to_string(),
    }
}

/// Check if all conditions of a rule match the attributes.
fn rule_matches(rule: &AbacRule, attrs: &AccessAttributes) -> bool {
    rule.conditions.iter().all(|cond| condition_matches(cond, attrs))
}

fn condition_matches(cond: &AbacCondition, attrs: &AccessAttributes) -> bool {
    let attr_set = match cond.target.as_str() {
        "user" => &attrs.user,
        "resource" => &attrs.resource,
        "environment" => &attrs.environment,
        _ => return false,
    };

    let actual = match attr_set.get(&cond.key) {
        Some(v) => v,
        None => return false,
    };

    match cond.operator {
        ConditionOp::Equals => actual == &cond.value,
        ConditionOp::NotEquals => actual != &cond.value,
        ConditionOp::Contains => {
            if let (Some(haystack), Some(needle)) = (actual.as_str(), cond.value.as_str()) {
                haystack.contains(needle)
            } else {
                false
            }
        }
        ConditionOp::In => {
            if let Some(arr) = cond.value.as_array() {
                arr.contains(actual)
            } else {
                false
            }
        }
        ConditionOp::GreaterThan => {
            match (actual.as_f64(), cond.value.as_f64()) {
                (Some(a), Some(b)) => a > b,
                _ => false,
            }
        }
        ConditionOp::LessThan => {
            match (actual.as_f64(), cond.value.as_f64()) {
                (Some(a), Some(b)) => a < b,
                _ => false,
            }
        }
    }
}

/// Load ABAC rules from a JSON string (stored in the policies table).
pub fn parse_rules(json: &str) -> Result<Vec<AbacRule>> {
    let rules: Vec<AbacRule> = serde_json::from_str(json)?;
    Ok(rules)
}
