// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Core field-name matching and value masking primitives.

mod default_sensitive_fields;
mod field_name;
mod field_sanitize_policy;
mod field_sanitizer;
mod mask_policies;
mod mask_policy;
mod name_match_mode;
mod redacted_debug;
mod sensitive_field_preset;
mod sensitive_fields;
mod sensitivity_level;

pub use default_sensitive_fields::DEFAULT_EXTRA_FIELDS;
pub use field_name::canonicalize_field_name;
pub use field_sanitize_policy::FieldSanitizePolicy;
pub use field_sanitizer::FieldSanitizer;
pub use mask_policies::MaskPolicies;
pub use mask_policy::MaskPolicy;
pub use name_match_mode::NameMatchMode;
pub use redacted_debug::{
    RedactedDebug,
    redacted_debug,
};
pub use sensitive_field_preset::SensitiveFieldPreset;
pub use sensitive_fields::SensitiveFields;
pub use sensitivity_level::SensitivityLevel;
