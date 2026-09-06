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
pub(crate) fn inspect_borrowed_value(session: &mut dyn RuntimeSession, value: &Value) {
    if session.policy().is_disabled() {
        return;
    }
    if session.admit_json_value(value) {
        inspect_value(session, value, true);
    }
}

/// Classifies a parsed JSON subtree using the active base policy.
fn inspect_value(session: &mut dyn RuntimeSession, value: &Value, unkeyed: bool) {
    match value {
        Value::Array(values) => {
            for value in values {
                inspect_value(session, value, true);
            }
        }
        Value::Object(entries) => {
            for (key, value) in entries {
                match session.policy().resolve_field(key) {
                    ResolvedField::Sensitive { sensitivity } => {
                        session.observe_sensitivity(sensitivity);
                    }
                    ResolvedField::PassThrough => inspect_value(session, value, false),
                }
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
