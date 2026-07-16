// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use super::SensitivityLevel;

/// Built-in sensitive field names not covered by any
/// [`super::SensitiveFieldPreset`].
///
/// Used by [`crate::SensitiveFields::default`] together with all presets.
pub const DEFAULT_EXTRA_FIELDS: &[(&str, SensitivityLevel)] = &[
    ("auth_app_token", SensitivityLevel::High),
    ("auth_user_token", SensitivityLevel::High),
    ("connection_string", SensitivityLevel::Secret),
    ("database_uri", SensitivityLevel::Secret),
    ("database_url", SensitivityLevel::Secret),
    ("license_key", SensitivityLevel::Medium),
    ("mysql_pwd", SensitivityLevel::Secret),
    ("rediscli_auth", SensitivityLevel::Secret),
    ("sig", SensitivityLevel::Secret),
    ("signature", SensitivityLevel::Secret),
];
