// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable field classification and value-masking primitives.

mod allow_rule;
mod field_classification;
mod field_name_matching;
mod global_default_already_set;
pub(crate) mod internal;
mod mask_policy;
mod masking_policy;
mod policy_error;
mod redaction_policy;
mod redaction_policy_builder;
mod sensitive_field_preset;
mod sensitive_field_rule;
mod sensitivity;

pub use allow_rule::AllowRule;
pub use field_classification::FieldClassification;
pub use field_name_matching::FieldNameMatching;
pub use global_default_already_set::GlobalDefaultAlreadySet;
pub use mask_policy::MaskPolicy;
pub use masking_policy::MaskingPolicy;
pub use policy_error::PolicyError;
pub use redaction_policy::RedactionPolicy;
pub use redaction_policy_builder::RedactionPolicyBuilder;
pub use sensitive_field_preset::SensitiveFieldPreset;
pub use sensitive_field_rule::SensitiveFieldRule;
pub use sensitivity::Sensitivity;
