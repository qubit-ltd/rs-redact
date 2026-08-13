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
use serde_json::to_string;

use super::internal::JsonRedactionState;
use super::internal::JsonUnkeyedValuePolicy;
use crate::RedactionPolicy;
use crate::Sensitivity;

/// Replaces JSON text with its compact redacted representation.
///
/// Invalid JSON is replaced with the configured Secret opaque mask so callers
/// never need to choose between propagating a parse error and exposing input.
///
/// # Resource Use
///
/// This explicit data transformation parses and allocates the complete JSON
/// value. It intentionally does not apply
/// [`InputOutputLimit`](crate::InputOutputLimit), which only bounds diagnostic
/// rendering; callers processing untrusted input must enforce their own
/// request-size limit before calling this function. The policy's
/// [`JsonDepthLimit`](crate::JsonDepthLimit) always applies and replaces an
/// over-depth subtree without visiting its descendants.
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
    let _ = state.redact(&mut value);
    to_string(&value).expect("JSON value serialization is infallible")
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
