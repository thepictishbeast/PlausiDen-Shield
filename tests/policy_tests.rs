//! Six-layer policy engine tests.
//!
//! Tests ABAC, MAC, SoD, and the full policy engine evaluation.

use std::collections::{HashMap, HashSet};

use plausiden_shield::auth::abac::{
    self, AbacCondition, AbacRule, AccessAttributes, ConditionOp, PolicyEffect,
};
use plausiden_shield::auth::mac::{self, SecurityLabel};
use plausiden_shield::auth::policy_engine::{AccessRequest, PolicyEngine};
use plausiden_shield::auth::rbac::{Permission, Role};
use plausiden_shield::auth::sod::{self, SodConstraint};

// --- MAC tests ---

#[test]
fn mac_public_access_always_allowed() {
    let result = mac::evaluate(SecurityLabel::Public, SecurityLabel::Public);
    assert!(result.allowed);
}

#[test]
fn mac_restricted_resource_needs_restricted_clearance() {
    let result = mac::evaluate(SecurityLabel::Internal, SecurityLabel::Restricted);
    assert!(!result.allowed, "Internal clearance cannot access restricted resources");
}

#[test]
fn mac_higher_clearance_accesses_lower_resources() {
    let result = mac::evaluate(SecurityLabel::Restricted, SecurityLabel::Public);
    assert!(result.allowed);
    let result = mac::evaluate(SecurityLabel::Confidential, SecurityLabel::Internal);
    assert!(result.allowed);
}

#[test]
fn mac_equal_clearance_allowed() {
    let result = mac::evaluate(SecurityLabel::Confidential, SecurityLabel::Confidential);
    assert!(result.allowed);
}

#[test]
fn security_label_ordering() {
    assert!(SecurityLabel::Restricted > SecurityLabel::Confidential);
    assert!(SecurityLabel::Confidential > SecurityLabel::Internal);
    assert!(SecurityLabel::Internal > SecurityLabel::Public);
}

#[test]
fn security_label_from_str() {
    assert_eq!(SecurityLabel::from_str_loose("public"), Some(SecurityLabel::Public));
    assert_eq!(SecurityLabel::from_str_loose("RESTRICTED"), Some(SecurityLabel::Restricted));
    assert_eq!(SecurityLabel::from_str_loose("bogus"), None);
}

// --- ABAC tests ---

fn test_attrs(dept: &str) -> AccessAttributes {
    let mut user = HashMap::new();
    user.insert("department".to_string(), serde_json::json!(dept));
    AccessAttributes {
        user,
        resource: HashMap::new(),
        action: "view".to_string(),
        environment: HashMap::new(),
    }
}

#[test]
fn abac_allow_rule_matches() {
    let rules = vec![AbacRule {
        name: "engineering-access".to_string(),
        conditions: vec![AbacCondition {
            target: "user".to_string(),
            key: "department".to_string(),
            operator: ConditionOp::Equals,
            value: serde_json::json!("engineering"),
        }],
        effect: PolicyEffect::Allow,
    }];

    let result = abac::evaluate(&rules, &test_attrs("engineering"));
    assert!(result.allowed);
    assert_eq!(result.matched_rules, vec!["engineering-access"]);
}

#[test]
fn abac_no_match_defaults_to_deny() {
    let rules = vec![AbacRule {
        name: "engineering-access".to_string(),
        conditions: vec![AbacCondition {
            target: "user".to_string(),
            key: "department".to_string(),
            operator: ConditionOp::Equals,
            value: serde_json::json!("engineering"),
        }],
        effect: PolicyEffect::Allow,
    }];

    let result = abac::evaluate(&rules, &test_attrs("marketing"));
    assert!(!result.allowed);
    assert!(result.reason.contains("No ABAC rule matched"));
}

#[test]
fn abac_deny_overrides_allow() {
    let rules = vec![
        AbacRule {
            name: "allow-all".to_string(),
            conditions: vec![AbacCondition {
                target: "user".to_string(),
                key: "department".to_string(),
                operator: ConditionOp::Equals,
                value: serde_json::json!("engineering"),
            }],
            effect: PolicyEffect::Allow,
        },
        AbacRule {
            name: "deny-engineering".to_string(),
            conditions: vec![AbacCondition {
                target: "user".to_string(),
                key: "department".to_string(),
                operator: ConditionOp::Equals,
                value: serde_json::json!("engineering"),
            }],
            effect: PolicyEffect::Deny,
        },
    ];

    let result = abac::evaluate(&rules, &test_attrs("engineering"));
    assert!(!result.allowed, "Deny should override allow");
}

#[test]
fn abac_condition_operators() {
    // NotEquals
    let rules = vec![AbacRule {
        name: "not-intern".to_string(),
        conditions: vec![AbacCondition {
            target: "user".to_string(),
            key: "department".to_string(),
            operator: ConditionOp::NotEquals,
            value: serde_json::json!("intern"),
        }],
        effect: PolicyEffect::Allow,
    }];
    let result = abac::evaluate(&rules, &test_attrs("engineering"));
    assert!(result.allowed);
    let result = abac::evaluate(&rules, &test_attrs("intern"));
    assert!(!result.allowed);
}

#[test]
fn abac_contains_operator() {
    let rules = vec![AbacRule {
        name: "eng-prefix".to_string(),
        conditions: vec![AbacCondition {
            target: "user".to_string(),
            key: "department".to_string(),
            operator: ConditionOp::Contains,
            value: serde_json::json!("eng"),
        }],
        effect: PolicyEffect::Allow,
    }];

    let result = abac::evaluate(&rules, &test_attrs("engineering"));
    assert!(result.allowed);
    let result = abac::evaluate(&rules, &test_attrs("marketing"));
    assert!(!result.allowed);
}

#[test]
fn abac_in_operator() {
    let rules = vec![AbacRule {
        name: "allowed-depts".to_string(),
        conditions: vec![AbacCondition {
            target: "user".to_string(),
            key: "department".to_string(),
            operator: ConditionOp::In,
            value: serde_json::json!(["engineering", "security"]),
        }],
        effect: PolicyEffect::Allow,
    }];

    let result = abac::evaluate(&rules, &test_attrs("engineering"));
    assert!(result.allowed);
    let result = abac::evaluate(&rules, &test_attrs("marketing"));
    assert!(!result.allowed);
}

#[test]
fn abac_numeric_operators() {
    let mut user = HashMap::new();
    user.insert("risk_score".to_string(), serde_json::json!(85.0));
    let attrs = AccessAttributes {
        user,
        resource: HashMap::new(),
        action: "view".to_string(),
        environment: HashMap::new(),
    };

    let rules = vec![AbacRule {
        name: "high-risk-deny".to_string(),
        conditions: vec![AbacCondition {
            target: "user".to_string(),
            key: "risk_score".to_string(),
            operator: ConditionOp::GreaterThan,
            value: serde_json::json!(80.0),
        }],
        effect: PolicyEffect::Deny,
    }];

    let result = abac::evaluate(&rules, &attrs);
    assert!(!result.allowed);
}

#[test]
fn abac_parse_rules_from_json() {
    let json = r#"[{
        "name": "test",
        "conditions": [{"target": "user", "key": "dept", "operator": "equals", "value": "eng"}],
        "effect": "allow"
    }]"#;
    let rules = abac::parse_rules(json).unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "test");
}

// --- SoD tests ---

#[test]
fn sod_no_constraints_allows() {
    let constraints: Vec<SodConstraint> = vec![];
    let prior = HashSet::new();
    let result = sod::evaluate(&constraints, "deploy", &prior);
    assert!(result.allowed);
}

#[test]
fn sod_detects_conflict() {
    let constraints = vec![SodConstraint {
        name: "deploy-approve-separation".to_string(),
        conflicting_actions: HashSet::from(["deploy".to_string(), "approve".to_string()]),
        max_per_user: 1,
    }];

    let mut prior = HashSet::new();
    prior.insert("deploy".to_string());

    let result = sod::evaluate(&constraints, "approve", &prior);
    assert!(!result.allowed);
    assert_eq!(result.violated_constraints, vec!["deploy-approve-separation"]);
}

#[test]
fn sod_no_conflict_when_different_actions() {
    let constraints = vec![SodConstraint {
        name: "deploy-approve-separation".to_string(),
        conflicting_actions: HashSet::from(["deploy".to_string(), "approve".to_string()]),
        max_per_user: 1,
    }];

    let mut prior = HashSet::new();
    prior.insert("view".to_string());

    let result = sod::evaluate(&constraints, "deploy", &prior);
    assert!(result.allowed);
}

#[test]
fn sod_parse_constraints_from_json() {
    let json = r#"[{
        "name": "test",
        "conflicting_actions": ["create", "approve"],
        "max_per_user": 1
    }]"#;
    let constraints = sod::parse_constraints(json).unwrap();
    assert_eq!(constraints.len(), 1);
    assert_eq!(constraints[0].name, "test");
}

// --- Full policy engine tests ---

fn make_request(
    role: Role,
    permission: Permission,
    user_clearance: SecurityLabel,
    resource_label: SecurityLabel,
) -> AccessRequest {
    AccessRequest {
        user_id: 1,
        role,
        permission,
        user_clearance,
        resource_label,
        attributes: AccessAttributes {
            user: HashMap::new(),
            resource: HashMap::new(),
            action: "test".to_string(),
            environment: HashMap::new(),
        },
        action: "test".to_string(),
        prior_actions: HashSet::new(),
    }
}

#[test]
fn engine_allows_admin_with_clearance() {
    let engine = PolicyEngine::new();
    let req = make_request(
        Role::Admin,
        Permission::ManageFirewall,
        SecurityLabel::Restricted,
        SecurityLabel::Confidential,
    );
    let decision = engine.evaluate(&req);
    assert!(decision.allowed);
    assert!(decision.layers.summary.contains("GRANTED"));
}

#[test]
fn engine_denies_on_rbac_failure() {
    let engine = PolicyEngine::new();
    let req = make_request(
        Role::Client,
        Permission::ManageFirewall,
        SecurityLabel::Restricted,
        SecurityLabel::Public,
    );
    let decision = engine.evaluate(&req);
    assert!(!decision.allowed);
    assert!(!decision.layers.rbac.allowed);
    assert!(decision.layers.summary.contains("DENIED"));
}

#[test]
fn engine_denies_on_mac_failure() {
    let engine = PolicyEngine::new();
    let req = make_request(
        Role::Admin,
        Permission::ManageFirewall,
        SecurityLabel::Public,
        SecurityLabel::Restricted,
    );
    let decision = engine.evaluate(&req);
    assert!(!decision.allowed);
    assert!(!decision.layers.mac.allowed);
}

#[test]
fn engine_denies_on_sod_violation() {
    let mut engine = PolicyEngine::new();
    engine.set_sod_constraints(vec![SodConstraint {
        name: "modify-audit-sep".to_string(),
        conflicting_actions: HashSet::from(["modify".to_string(), "audit".to_string()]),
        max_per_user: 1,
    }]);

    let mut prior = HashSet::new();
    prior.insert("modify".to_string());

    let req = AccessRequest {
        user_id: 1,
        role: Role::Admin,
        permission: Permission::ManageFirewall,
        user_clearance: SecurityLabel::Restricted,
        resource_label: SecurityLabel::Public,
        attributes: AccessAttributes {
            user: HashMap::new(),
            resource: HashMap::new(),
            action: "audit".to_string(),
            environment: HashMap::new(),
        },
        action: "audit".to_string(),
        prior_actions: prior,
    };

    let decision = engine.evaluate(&req);
    assert!(!decision.allowed);
    assert!(!decision.layers.sod.allowed);
}

#[test]
fn engine_denies_on_abac_denial() {
    let mut engine = PolicyEngine::new();
    engine.set_abac_rules(vec![AbacRule {
        name: "deny-all".to_string(),
        conditions: vec![AbacCondition {
            target: "user".to_string(),
            key: "banned".to_string(),
            operator: ConditionOp::Equals,
            value: serde_json::json!(true),
        }],
        effect: PolicyEffect::Deny,
    }]);

    let mut user_attrs = HashMap::new();
    user_attrs.insert("banned".to_string(), serde_json::json!(true));

    let req = AccessRequest {
        user_id: 1,
        role: Role::Admin,
        permission: Permission::ViewDashboard,
        user_clearance: SecurityLabel::Restricted,
        resource_label: SecurityLabel::Public,
        attributes: AccessAttributes {
            user: user_attrs,
            resource: HashMap::new(),
            action: "view".to_string(),
            environment: HashMap::new(),
        },
        action: "view".to_string(),
        prior_actions: HashSet::new(),
    };

    let decision = engine.evaluate(&req);
    assert!(!decision.allowed);
    assert!(!decision.layers.abac.allowed);
}

#[test]
fn engine_reasoning_chain_fully_populated() {
    let engine = PolicyEngine::new();
    let req = make_request(
        Role::Admin,
        Permission::ViewDashboard,
        SecurityLabel::Internal,
        SecurityLabel::Internal,
    );
    let decision = engine.evaluate(&req);
    // All layers should be populated regardless of outcome.
    assert!(decision.layers.rbac.allowed);
    assert!(decision.layers.abac.allowed);
    assert!(decision.layers.pbac.allowed);
    assert!(decision.layers.mac.allowed);
    assert!(decision.layers.sod.allowed);
    assert!(decision.layers.contextual.allowed);
    assert!(!decision.layers.summary.is_empty());
}
