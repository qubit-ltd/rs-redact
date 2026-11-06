// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Bounded serialization of borrowed JSON values and output provenance.

use serde_json::Value;
use serde_json::to_writer;

pub(super) use super::internal::BoundedJsonRedaction;
use super::internal::JsonRedactionState;
use crate::RedactionPolicy;
use crate::runtime::OperationByteSink;

/// Redacts a borrowed parsed JSON value without cloning or reparsing it.
///
/// # Parameters
///
/// - `value`: Parsed JSON tree borrowed for policy-aware serialization.
/// - `policy`: Field rules and masking policy applied to the borrowed tree.
/// - `max_output`: Maximum serialized bytes retained by the output sink; safe
///   fallback text may exceed this allowance and requires caller-side bounding.
///
/// # Returns
///
/// `Complete` contains compact redacted JSON, or the policy's opaque secret
/// mask if the retained bytes cannot be converted to UTF-8. `Truncated`
/// contains `<truncated>` when serialization fails, including output-budget
/// exhaustion. This parsed-value path never returns `Invalid`.
#[must_use]
pub(super) fn redacted_json_value_bounded(
    value: &Value,
    policy: &RedactionPolicy,
    max_output: usize,
) -> BoundedJsonRedaction {
    let mut writer = OperationByteSink::new(max_output);
    let state = JsonRedactionState::from_policy(policy);
    let redacted = state.redact(value);
    if to_writer(&mut writer, &redacted).is_err() {
        return BoundedJsonRedaction::Truncated("<truncated>".to_owned());
    }
    BoundedJsonRedaction::Complete(
        writer
            .into_string()
            .unwrap_or_else(|| policy.masking().mask_opaque(crate::Sensitivity::Secret).to_owned()),
    )
}
