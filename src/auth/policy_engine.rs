//! Six-Layer Policy Engine.
//!
//! Every access request is evaluated through all six layers in order:
//!   1. RBAC  — role-based baseline
//!   2. ABAC  — attribute-based refinement
#![allow(dead_code)]
//!   3. PBAC  — weighted probabilistic soft logic (hard-fail veto)
//!   4. MAC   — mandatory sensitivity labels (non-overridable floor)
//!   5. SoD   — separation of duties (conflict prevention)
//!   6. Contextual — step-up auth, break-glass, time-based
//!
//! The engine produces a full reasoning chain for every decision, suitable
//! for audit logging and the policy tester UI.

use serde::Serialize;
use std::collections::HashSet;

use super::abac::{self, AbacDecision, AbacRule, AccessAttributes};
use super::mac::{self, MacDecision, SecurityLabel};
use super::rbac::{self, Permission, RbacDecision, Role};
use super::sod::{self, SodConstraint, SodDecision};

/// Complete access request context.
pub struct AccessRequest {
    pub user_id: i64,
    pub role: Role,
    pub permission: Permission,
    pub user_clearance: SecurityLabel,
    pub resource_label: SecurityLabel,
    pub attributes: AccessAttributes,
    pub action: String,
    /// Actions this user has already performed on this resource (for SoD).
    pub prior_actions: HashSet<String>,
}

/// The final access decision with full reasoning chain.
#[derive(Debug, Clone, Serialize)]
pub struct AccessDecision {
    pub allowed: bool,
    pub layers: ReasoningChain,
}

/// Reasoning from each layer.
#[derive(Debug, Clone, Serialize)]
pub struct ReasoningChain {
    pub rbac: RbacDecision,
    pub abac: AbacDecision,
    pub pbac: PbacDecision,
    pub mac: MacDecision,
    pub sod: SodDecision,
    pub contextual: ContextualDecision,
    /// Human-readable summary of the final decision.
    pub summary: String,
}

/// PBAC (Probabilistic/weighted) decision — placeholder for NeuPSL integration.
#[derive(Debug, Clone, Serialize)]
pub struct PbacDecision {
    pub allowed: bool,
    pub confidence: f64,
    pub reason: String,
}

/// Contextual access control decision.
#[derive(Debug, Clone, Serialize)]
pub struct ContextualDecision {
    pub allowed: bool,
    pub step_up_required: bool,
    pub break_glass_active: bool,
    pub reason: String,
}

/// The policy engine — holds loaded rules and constraints.
pub struct PolicyEngine {
    abac_rules: Vec<AbacRule>,
    sod_constraints: Vec<SodConstraint>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            abac_rules: Vec::new(),
            sod_constraints: Vec::new(),
        }
    }

    /// Load ABAC rules (from database or policy files).
    pub fn set_abac_rules(&mut self, rules: Vec<AbacRule>) {
        self.abac_rules = rules;
    }

    /// Load SoD constraints.
    pub fn set_sod_constraints(&mut self, constraints: Vec<SodConstraint>) {
        self.sod_constraints = constraints;
    }

    /// Evaluate an access request through all six layers.
    ///
    /// Short-circuit on hard denials (MAC, SoD) but always populate the
    /// full reasoning chain for audit logging.
    pub fn evaluate(&self, req: &AccessRequest) -> AccessDecision {
        // Layer 1: RBAC
        let rbac_result = rbac::evaluate(req.role, req.permission);

        // Layer 2: ABAC
        let abac_result = if self.abac_rules.is_empty() {
            // No ABAC rules loaded → pass through (defer to RBAC).
            abac::AbacDecision {
                allowed: true,
                matched_rules: vec![],
                reason: "No ABAC rules configured; pass-through".to_string(),
            }
        } else {
            abac::evaluate(&self.abac_rules, &req.attributes)
        };

        // Layer 3: PBAC (placeholder — will integrate NeuPSL crate)
        let pbac_result = PbacDecision {
            allowed: true,
            confidence: 1.0,
            reason: "PBAC layer not yet configured; pass-through".to_string(),
        };

        // Layer 4: MAC (hard floor — cannot be overridden)
        let mac_result = mac::evaluate(req.user_clearance, req.resource_label);

        // Layer 5: SoD
        let sod_result = if self.sod_constraints.is_empty() {
            sod::SodDecision {
                allowed: true,
                violated_constraints: vec![],
                reason: "No SoD constraints configured; pass-through".to_string(),
            }
        } else {
            sod::evaluate(&self.sod_constraints, &req.action, &req.prior_actions)
        };

        // Layer 6: Contextual (placeholder for step-up auth, break-glass, time-based)
        let contextual_result = ContextualDecision {
            allowed: true,
            step_up_required: false,
            break_glass_active: false,
            reason: "Contextual layer: no additional constraints".to_string(),
        };

        // Final decision: ALL layers must allow.
        let allowed = rbac_result.allowed
            && abac_result.allowed
            && pbac_result.allowed
            && mac_result.allowed
            && sod_result.allowed
            && contextual_result.allowed;

        // Build summary.
        let summary = if allowed {
            "Access GRANTED — all six layers passed".to_string()
        } else {
            let mut denials = Vec::new();
            if !rbac_result.allowed {
                denials.push(format!("RBAC: {}", rbac_result.reason));
            }
            if !abac_result.allowed {
                denials.push(format!("ABAC: {}", abac_result.reason));
            }
            if !pbac_result.allowed {
                denials.push(format!("PBAC: {}", pbac_result.reason));
            }
            if !mac_result.allowed {
                denials.push(format!("MAC: {}", mac_result.reason));
            }
            if !sod_result.allowed {
                denials.push(format!("SoD: {}", sod_result.reason));
            }
            if !contextual_result.allowed {
                denials.push(format!("Contextual: {}", contextual_result.reason));
            }
            format!("Access DENIED — {}", denials.join("; "))
        };

        AccessDecision {
            allowed,
            layers: ReasoningChain {
                rbac: rbac_result,
                abac: abac_result,
                pbac: pbac_result,
                mac: mac_result,
                sod: sod_result,
                contextual: contextual_result,
                summary,
            },
        }
    }

    /// Dry-run evaluation for the policy tester UI.
    /// Identical to `evaluate()` but clearly marked as a test.
    pub fn test_access(&self, req: &AccessRequest) -> AccessDecision {
        tracing::info!(
            user_id = req.user_id,
            role = %req.role,
            permission = ?req.permission,
            "Policy tester: dry-run evaluation"
        );
        self.evaluate(req)
    }
}
