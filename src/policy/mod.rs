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
mod domain_redaction_limits;
mod domain_redaction_limits_error;
mod domain_traversal_admission;
mod domain_value_admission;
mod domain_value_scope;
pub mod field;
mod field_classification;
mod field_match_kind;
mod field_name_matching;
pub(crate) mod internal;
#[cfg(feature = "json")]
mod json_depth_limit;
#[cfg(feature = "json")]
mod json_depth_limit_error;
mod mask_policy;
pub mod masking;
mod masking_policy;
mod policy_error;
mod policy_location;
mod redaction_floor;
mod redaction_floor_builder;
mod redaction_limits;
mod redaction_policy;
mod redaction_policy_builder;
mod redaction_resource;
mod redaction_rules;
mod redaction_rules_builder;
mod resolved_field;
mod sensitive_field_preset;
mod sensitive_field_rule;
mod sensitivity;
#[cfg(feature = "json")]
mod unkeyed_json_value_policy;
mod unknown_field_policy;

pub use allow_rule::AllowRule;
pub use diagnostic_budget::InputOutputLimit;
pub use diagnostic_budget::InputOutputLimitBuilder;
pub use diagnostic_budget_error::DiagnosticBudgetError;
pub use domain_redaction_limits::DomainRedactionLimits;
pub use domain_redaction_limits::DomainRedactionLimitsBuilder;
pub use domain_redaction_limits_error::DomainRedactionLimitsError;
pub use domain_traversal_admission::DomainTraversalAdmission;
pub use domain_value_admission::DomainValueAdmission;
pub use domain_value_scope::DomainValueScope;
pub use field_classification::FieldClassification;
pub use field_match_kind::FieldMatchKind;
pub use field_name_matching::FieldNameMatching;
#[cfg(feature = "json")]
pub use json_depth_limit::JsonDepthLimit;
#[cfg(feature = "json")]
pub use json_depth_limit::JsonDepthLimitBuilder;
#[cfg(feature = "json")]
pub use json_depth_limit_error::JsonDepthLimitError;
pub use mask_policy::MaskPolicy;
pub use masking_policy::MaskingPolicy;
pub use masking_policy::MaskingPolicyBuilder;
pub use policy_error::PolicyError;
pub use policy_location::PolicyLocation;
pub use redaction_floor::RedactionFloor;
pub use redaction_floor_builder::RedactionFloorBuilder;
pub use redaction_limits::RedactionLimits;
pub use redaction_limits::RedactionLimitsBuilder;
pub use redaction_policy::RedactionPolicy;
pub use redaction_policy_builder::FieldsBuilder;
#[cfg(feature = "http")]
pub use redaction_policy_builder::HttpContextBuilderView;
#[cfg(feature = "http")]
pub use redaction_policy_builder::HttpPolicyBuilderView;
pub use redaction_policy_builder::LimitsBuilder;
pub use redaction_policy_builder::RedactionPolicyBuilder;
#[cfg(feature = "uri")]
pub use redaction_policy_builder::UriPolicyBuilderView;
pub(crate) use redaction_resource::RedactionResource;
pub use redaction_rules::RedactionRules;
pub(crate) use redaction_rules_builder::RedactionRulesBuilder;
pub(crate) use resolved_field::ResolvedField;
pub use sensitive_field_preset::SensitiveFieldPreset;
pub use sensitive_field_rule::SensitiveFieldRule;
pub use sensitivity::Sensitivity;
#[cfg(feature = "json")]
pub use unkeyed_json_value_policy::UnkeyedJsonValuePolicy;
pub use unknown_field_policy::UnknownFieldPolicy;

pub(crate) use crate::runtime::DiagnosticBudget;
pub(crate) use crate::runtime::DomainTruncation;
pub(crate) use crate::runtime::FragmentCompletion;
pub(crate) use crate::runtime::RedactionAdmission;
pub use crate::runtime::RedactionSession;
