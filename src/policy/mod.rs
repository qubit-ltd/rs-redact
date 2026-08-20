// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable field classification and value-masking primitives.

pub mod field;
pub(crate) mod internal;
pub mod masking;
mod policy_error;
mod policy_location;
mod redaction_limits;
mod redaction_policy;
mod redaction_policy_builder;
mod redaction_rules_builder;
mod resolved_field;
#[cfg(feature = "json")]
mod unkeyed_json_value_policy;

pub use field::AllowRule;
pub use field::FieldClassification;
pub use field::FieldMatchKind;
pub use field::FieldNameMatching;
pub use field::RedactionFloor;
pub use field::RedactionFloorBuilder;
pub use field::RedactionRules;
pub use field::SensitiveFieldPreset;
pub use field::SensitiveFieldRule;
pub use field::Sensitivity;
pub use field::UnknownFieldPolicy;
pub use masking::MaskPolicy;
pub use masking::MaskingPolicy;
pub use masking::MaskingPolicyBuilder;
pub use policy_error::PolicyError;
pub use policy_location::PolicyLocation;
pub use redaction_limits::RedactionLimits;
pub use redaction_limits::RedactionLimitsBuilder;
pub use redaction_policy::RedactionPolicy;
pub use redaction_policy_builder::FieldsBuilder;
#[cfg(feature = "http")]
pub use redaction_policy_builder::HttpContextBuilderView;
#[cfg(feature = "http")]
pub use redaction_policy_builder::HttpPolicyBuilderView;
pub use redaction_policy_builder::RedactionPolicyBuilder;
#[cfg(feature = "uri")]
pub use redaction_policy_builder::UriPolicyBuilderView;
pub(crate) use redaction_rules_builder::RedactionRulesBuilder;
pub(crate) use resolved_field::ResolvedField;
#[cfg(feature = "json")]
pub use unkeyed_json_value_policy::UnkeyedJsonValuePolicy;
