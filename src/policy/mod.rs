// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable field classification and value-masking primitives.

mod allow_rule;
mod diagnostic_budget;
mod diagnostic_budget_error;
mod diagnostic_input_budget;
mod field_classification;
mod field_match_kind;
mod field_name_matching;
mod global_default_already_set;
pub(crate) mod internal;
#[cfg(feature = "json")]
mod json_depth_budget;
#[cfg(feature = "json")]
mod json_depth_budget_error;
mod mask_policy;
mod masking_policy;
mod policy_error;
mod policy_location;
mod redaction_floor;
mod redaction_floor_builder;
mod redaction_floor_state;
mod redaction_limits;
mod redaction_policy;
mod redaction_policy_builder;
mod redaction_rules;
mod redaction_rules_builder;
mod resolved_field;
mod sensitive_field_preset;
mod sensitive_field_rule;
mod sensitivity;
mod unknown_field_policy;

pub use allow_rule::AllowRule;
pub use diagnostic_budget::DiagnosticBudget;
pub use diagnostic_budget_error::DiagnosticBudgetError;
pub use diagnostic_input_budget::DiagnosticInputBudget;
pub use field_classification::FieldClassification;
pub use field_match_kind::FieldMatchKind;
pub use field_name_matching::FieldNameMatching;
pub use global_default_already_set::GlobalDefaultAlreadySet;
#[cfg(feature = "json")]
pub use json_depth_budget::JsonDepthBudget;
#[cfg(feature = "json")]
pub use json_depth_budget_error::JsonDepthBudgetError;
pub use mask_policy::MaskPolicy;
pub use masking_policy::MaskingPolicy;
pub use policy_error::PolicyError;
pub use policy_location::PolicyLocation;
pub use redaction_floor::RedactionFloor;
pub use redaction_floor_builder::RedactionFloorBuilder;
pub use redaction_floor_state::RedactionFloorState;
pub use redaction_policy::RedactionPolicy;
pub use redaction_policy_builder::RedactionPolicyBuilder;
pub use redaction_rules::RedactionRules;
pub(crate) use redaction_rules_builder::RedactionRulesBuilder;
pub(crate) use resolved_field::ResolvedField;
pub use sensitive_field_preset::SensitiveFieldPreset;
pub use sensitive_field_rule::SensitiveFieldRule;
pub use sensitivity::Sensitivity;
pub use unknown_field_policy::UnknownFieldPolicy;
