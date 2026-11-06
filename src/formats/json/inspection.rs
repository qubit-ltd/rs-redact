// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Non-rendering sensitivity inspection for JSON documents.

use serde_json::Value;

use super::JsonAdmissionError;
use super::admit_json_text_value;
use crate::RedactionReason;
use crate::Sensitivity;
use crate::UnkeyedJsonValuePolicy;
use crate::policy::ResolvedField;
use crate::runtime::runtime_session::RuntimeSession;

/// Parses and completely classifies one JSON document.
///
/// Charges input admission before checking whether the policy is disabled.
/// Admission failures and invalid JSON are recorded in the session; no output
/// is rendered.
///
/// # Parameters
///
/// - `session`: Inspection transaction receiving accounting and sensitivity
///   observations.
/// - `text`: Borrowed JSON document to admit, parse, and classify.
///
/// # Panics
///
/// In debug builds, may panic if `session` is a rendering transaction rather
/// than an inspection transaction.
pub(crate) fn inspect_text(session: &mut dyn RuntimeSession, text: &str) {
    if !session.admit_input(text.len()) {
        return;
    }
    if session.policy().is_disabled() {
        return;
    }
    let value = match admit_json_text_value(session, text) {
        Ok(value) => value,
        Err(JsonAdmissionError::Invalid) => {
            session.fail_inspection(RedactionReason::InvalidJson);
            return;
        }
        Err(JsonAdmissionError::Limit) => return,
    };
    inspect_value(session, &value, true);
}

/// Classifies one already-parsed JSON value without rendering it.
///
/// Admits the complete value before checking whether the policy is disabled.
/// The value remains borrowed and is neither cloned nor modified.
///
/// # Parameters
///
/// - `session`: Inspection transaction receiving accounting and sensitivity
///   observations, including admission failures.
/// - `value`: Parsed JSON root to admit and classify.
///
/// # Panics
///
/// In debug builds, may panic if `session` is a rendering transaction rather
/// than an inspection transaction.
pub(crate) fn inspect_borrowed_value(session: &mut dyn RuntimeSession, value: &Value) {
    if session.admit_json_value(value) && !session.policy().is_disabled() {
        inspect_value(session, value, true);
    }
}

/// Classifies a parsed JSON subtree using the active base policy.
///
/// Traverses an already-admitted subtree and records sensitivity without
/// rendering or changing the borrowed value. Object keys are resolved through
/// the field policy; array elements are treated as unkeyed values.
///
/// # Parameters
///
/// - `session`: Inspection transaction receiving sensitivity observations.
/// - `value`: Already-admitted subtree to visit recursively.
/// - `unkeyed`: Whether a scalar at this position is subject to the unkeyed
///   value policy; `false` for an object field and `true` for a root or array
///   element.
///
/// # Panics
///
/// In debug builds, may panic if `session` is a rendering transaction rather
/// than an inspection transaction.
fn inspect_value(session: &mut dyn RuntimeSession, value: &Value, unkeyed: bool) {
    match value {
        Value::Array(values) => {
            for value in values {
                inspect_value(session, value, true);
            }
        }
        Value::Object(entries) => {
            for (key, value) in entries {
                if let ResolvedField::Sensitive { sensitivity } = session.policy().resolve_field(key) {
                    session.observe_sensitivity(sensitivity);
                }
                inspect_value(session, value, false);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
            if unkeyed && session.policy().unkeyed_json_value_policy() == UnkeyedJsonValuePolicy::Redact =>
        {
            session.observe_sensitivity(Sensitivity::Secret);
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}
