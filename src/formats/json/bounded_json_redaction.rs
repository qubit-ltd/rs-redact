// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! In-place conversion of JSON text to its compact redacted representation.

use serde_json::Value;
use serde_json::from_str;
use serde_json::to_writer;

use super::internal::JsonRedactionState;
use super::internal::JsonUnkeyedValuePolicy;
use crate::RedactionPolicy;
use crate::Sensitivity;
use crate::runtime::OperationByteSink;

/// Bounded JSON text paired with whether budget enforcement omitted content.
pub(super) enum BoundedJsonRedaction {
    /// The complete redacted representation fit within the bound.
    Complete(String),
    /// A non-empty safe substitute represents budget-omitted content.
    Truncated(String),
    /// A syntactically invalid source was replaced without exposing it.
    Invalid(String),
}

impl BoundedJsonRedaction {
    /// Consumes this result into its text and truncation provenance.
    #[must_use]
    #[inline]
    pub(super) fn into_parts(self) -> (String, bool, bool) {
        match self {
            Self::Complete(text) => (text, false, false),
            Self::Truncated(text) => (text, true, false),
            Self::Invalid(text) => (text, false, true),
        }
    }
}

/// Redacts JSON text while enforcing the supplied output bound.
pub(super) fn redacted_json_text_bounded(
    text: &str,
    policy: &RedactionPolicy,
    max_output: usize,
) -> BoundedJsonRedaction {
    let Ok(mut value) = from_str::<Value>(text) else {
        return BoundedJsonRedaction::Invalid(opaque_secret(policy));
    };
    let unkeyed = match policy.unkeyed_json_value_policy() {
        crate::UnkeyedJsonValuePolicy::PassThrough => JsonUnkeyedValuePolicy::PassThrough,
        crate::UnkeyedJsonValuePolicy::Redact => {
            let marker = policy.masking().mask_opaque(Sensitivity::Secret);
            JsonUnkeyedValuePolicy::Redact { marker }
        }
    };
    JsonRedactionState::from_policy(policy, unkeyed).redact(&mut value);
    let mut writer = OperationByteSink::new(max_output);
    if to_writer(&mut writer, &value).is_err() {
        return BoundedJsonRedaction::Truncated("<truncated>".to_owned());
    }
    BoundedJsonRedaction::Complete(writer.into_string().unwrap_or_else(|| opaque_secret(policy)))
}

/// Returns the configured opaque replacement for invalid JSON text.
///
/// # Parameters
///
/// * policy - Immutable masking configuration.
///
/// # Returns
///
/// An owned complete replacement selected at Secret sensitivity.
fn opaque_secret(policy: &RedactionPolicy) -> String {
    policy.masking().mask_opaque(Sensitivity::Secret).to_owned()
}
