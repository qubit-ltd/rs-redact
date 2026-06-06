// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use super::{
    MaskPolicies,
    SensitiveFields,
};

/// Policy used by [`crate::FieldSanitizer`] for field-value sanitization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSanitizePolicy {
    /// Sensitive fields and their sensitivity levels.
    pub sensitive_fields: SensitiveFields,
    /// Mask policies for each sensitivity level.
    pub mask_policies: MaskPolicies,
}

impl FieldSanitizePolicy {
    /// Creates a policy without built-in sensitive fields.
    ///
    /// # Returns
    ///
    /// Empty sensitive field policy with default mask policies.
    pub fn empty() -> Self {
        Self {
            sensitive_fields: SensitiveFields::new(),
            mask_policies: MaskPolicies::default(),
        }
    }
}

impl Default for FieldSanitizePolicy {
    /// Creates a policy with built-in sensitive fields and default masks.
    fn default() -> Self {
        Self {
            sensitive_fields: SensitiveFields::default(),
            mask_policies: MaskPolicies::default(),
        }
    }
}
