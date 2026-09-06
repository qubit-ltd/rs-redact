// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Owned adapter state for a borrowed Display value and policy.

use std::fmt::Display;

use crate::RedactionPolicy;
use crate::Sensitivity;

/// Keeps the textual adapter alive for the complete field serialization.
#[doc(hidden)]
pub struct RedactedDisplaySerializeRef<'value, 'policy, T: ?Sized> {
    /// Borrowed raw field, never formatted at construction.
    value: &'value T,
    /// Parent serialization policy.
    policy: &'policy RedactionPolicy,
    /// Final level declared on the field.
    level: Sensitivity,
}

impl<'value, 'policy, T: ?Sized> RedactedDisplaySerializeRef<'value, 'policy, T> {
    /// Captures the raw reference and field decision without invoking Display.
    pub fn new(value: &'value T, policy: &'policy RedactionPolicy, level: Sensitivity) -> Self {
        Self {
            value,
            policy,
            level,
        }
    }
}

impl<T: Display + ?Sized> serde::Serialize for RedactedDisplaySerializeRef<'_, '_, T> {
    /// Executes one bounded textual scalar serialization.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        super::redact_level_serialize::serialize_display_text(
            self.value,
            serializer,
            self.policy,
            self.level,
        )
    }
}
