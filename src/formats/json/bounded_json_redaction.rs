// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! In-place conversion of JSON text to its compact redacted representation.

use std::io;
use std::io::Write;

use qubit_budget::ResourceBudget;
use serde_json::Value;
use serde_json::from_str;
use serde_json::to_string;
use serde_json::to_writer;

use super::internal::JsonRedactionState;
use super::internal::JsonUnkeyedValuePolicy;
use crate::RedactionPolicy;
use crate::Sensitivity;
use crate::policy::RedactionResource;

/// Bounded JSON text paired with whether budget enforcement omitted content.
pub(super) enum BoundedJsonRedaction {
    /// The complete redacted representation fit within the bound.
    Complete(String),
    /// A non-empty safe substitute represents budget-omitted content.
    Truncated(String),
}

impl BoundedJsonRedaction {
    /// Consumes this result into its text and truncation provenance.
    #[must_use]
    #[inline]
    pub(super) fn into_parts(self) -> (String, bool) {
        match self {
            Self::Complete(text) => (text, false),
            Self::Truncated(text) => (text, true),
        }
    }
}

/// Replaces JSON text with its compact redacted representation.
///
/// Invalid JSON is replaced with the configured Secret opaque mask so callers
/// never need to choose between propagating a parse error and exposing input.
///
/// # Resource Use
///
/// Redaction of the materialized [`serde_json::Value`] uses an explicit tree
/// stack and applies the configured JSON value limits fail closed.
/// JSON parsing and final serialization retain the resource and recursion
/// boundaries of `serde_json`. This guarantee does not apply to the lazy
/// [`RedactedJson`](crate::formats::json::RedactedJson) `Debug` or Serde
/// rendering path.
///
/// # Parameters
///
/// * text - JSON text replaced in place.
/// * policy - Immutable policy used to classify every object key.
pub fn redact_json_text_in_place(text: &mut String, policy: &RedactionPolicy) {
    *text = redacted_json_text(text, policy);
}

/// Produces compact redacted JSON text without mutating the input.
///
/// # Parameters
///
/// * text - JSON text to parse and redact.
/// * policy - Immutable policy used to classify every object key.
///
/// # Returns
///
/// Compact redacted JSON for valid input, or the configured Secret opaque mask
/// for invalid input.
pub(crate) fn redacted_json_text(text: &str, policy: &RedactionPolicy) -> String {
    let Ok(mut value) = from_str::<Value>(text) else {
        return opaque_secret(policy);
    };
    let unkeyed = match policy.unkeyed_json_value_policy() {
        crate::UnkeyedJsonValuePolicy::PassThrough => JsonUnkeyedValuePolicy::PassThrough,
        crate::UnkeyedJsonValuePolicy::Redact => {
            let marker = policy.masking().mask_opaque(Sensitivity::Secret);
            JsonUnkeyedValuePolicy::Redact {
                marker,
                truncated_marker: marker,
            }
        }
    };
    let mut state = JsonRedactionState::from_policy(policy, unkeyed, None);
    if state.redact(&mut value).is_mask_budget_exhausted() {
        return opaque_secret(policy);
    }
    to_string(&value).expect("JSON value serialization is infallible")
}

/// Redacts JSON text while enforcing the supplied output bound.
pub(super) fn redacted_json_text_bounded(
    text: &str,
    policy: &RedactionPolicy,
    max_output: usize,
) -> BoundedJsonRedaction {
    let Ok(mut value) = from_str::<Value>(text) else {
        return BoundedJsonRedaction::Complete(opaque_secret(policy));
    };
    let unkeyed = match policy.unkeyed_json_value_policy() {
        crate::UnkeyedJsonValuePolicy::PassThrough => JsonUnkeyedValuePolicy::PassThrough,
        crate::UnkeyedJsonValuePolicy::Redact => {
            let marker = policy.masking().mask_opaque(Sensitivity::Secret);
            JsonUnkeyedValuePolicy::Redact {
                marker,
                truncated_marker: marker,
            }
        }
    };
    let mut mask_budget = ResourceBudget::new(RedactionResource::Mask, max_output);
    if JsonRedactionState::from_policy(policy, unkeyed, Some(&mut mask_budget))
        .redact(&mut value)
        .is_mask_budget_exhausted()
    {
        return BoundedJsonRedaction::Truncated(opaque_secret(policy));
    }
    /// Byte sink that rejects writes exceeding its output bound.
    struct Bounded(Vec<u8>, usize);
    impl Write for Bounded {
        /// Appends bytes when the bounded sink can retain the complete write.
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0.len().saturating_add(bytes.len()) > self.1 {
                return Err(io::Error::from(io::ErrorKind::WriteZero));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        /// Flushes the bounded sink; no buffered data exists.
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Bounded(Vec::new(), max_output);
    if to_writer(&mut writer, &value).is_err() {
        return BoundedJsonRedaction::Truncated("<truncated>".to_owned());
    }
    BoundedJsonRedaction::Complete(String::from_utf8(writer.0).unwrap_or_else(|_| opaque_secret(policy)))
}

/// Redacts a JSON value while enforcing the supplied output bound.
pub(super) fn redacted_json_value_bounded(
    source: &Value,
    policy: &RedactionPolicy,
    max_output: usize,
) -> BoundedJsonRedaction {
    let mut value = source.clone();
    let unkeyed = match policy.unkeyed_json_value_policy() {
        crate::UnkeyedJsonValuePolicy::PassThrough => JsonUnkeyedValuePolicy::PassThrough,
        crate::UnkeyedJsonValuePolicy::Redact => {
            let marker = policy.masking().mask_opaque(Sensitivity::Secret);
            JsonUnkeyedValuePolicy::Redact {
                marker,
                truncated_marker: marker,
            }
        }
    };
    let mut mask_budget = ResourceBudget::new(RedactionResource::Mask, max_output);
    if JsonRedactionState::from_policy(policy, unkeyed, Some(&mut mask_budget))
        .redact(&mut value)
        .is_mask_budget_exhausted()
    {
        return BoundedJsonRedaction::Truncated(opaque_secret(policy));
    }
    /// Byte sink that rejects writes exceeding its output bound.
    struct Bounded(Vec<u8>, usize);
    impl Write for Bounded {
        /// Appends bytes when the bounded sink can retain the complete write.
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0.len().saturating_add(bytes.len()) > self.1 {
                return Err(io::Error::from(io::ErrorKind::WriteZero));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        /// Flushes the bounded sink; no buffered data exists.
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Bounded(Vec::new(), max_output);
    if to_writer(&mut writer, &value).is_err() {
        return BoundedJsonRedaction::Truncated("<truncated>".to_owned());
    }
    BoundedJsonRedaction::Complete(String::from_utf8(writer.0).unwrap_or_else(|_| opaque_secret(policy)))
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
