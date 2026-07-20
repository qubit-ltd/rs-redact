// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
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
mod log_escape;
mod mask_policies;
mod name_match_mode;
mod redacted_debug;
mod sensitive_fields;

pub use crate::policy::{
    MaskPolicy,
    SensitiveFieldPreset,
    Sensitivity as SensitivityLevel,
};

pub use field_name::canonicalize_field_name;
pub use field_sanitize_policy::FieldSanitizePolicy;
pub use field_sanitizer::FieldSanitizer;
pub use log_escape::escape_log_control_characters;
pub use mask_policies::MaskPolicies;
pub use name_match_mode::NameMatchMode;
pub use redacted_debug::{
    RedactedDebug,
    redacted_debug,
};
pub use sensitive_fields::SensitiveFields;
