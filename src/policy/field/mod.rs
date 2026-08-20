// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Field classification policy and its immutable rule views.

mod allow_rule;
mod field_classification;
mod field_match_kind;
mod field_name_matching;
mod redaction_floor;
mod redaction_floor_builder;
mod redaction_rules;
mod sensitive_field_preset;
mod sensitive_field_rule;
mod sensitivity;
mod unknown_field_policy;

pub use allow_rule::AllowRule;
pub use field_classification::FieldClassification;
pub use field_match_kind::FieldMatchKind;
pub use field_name_matching::FieldNameMatching;
pub use redaction_floor::RedactionFloor;
pub use redaction_floor_builder::RedactionFloorBuilder;
pub use redaction_rules::RedactionRules;
pub use sensitive_field_preset::SensitiveFieldPreset;
pub use sensitive_field_rule::SensitiveFieldRule;
pub use sensitivity::Sensitivity;
pub use unknown_field_policy::UnknownFieldPolicy;
