// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Non-rendering sensitivity inspection for JSON documents.

use serde_json::Value;
use serde_json::from_str;

use super::admit_json_text_structure;
use crate::RedactionReason;
use crate::RedactionSession;
use crate::Sensitivity;
use crate::UnkeyedJsonValuePolicy;
use crate::policy::ResolvedField;

/// Parses and completely classifies one JSON document.
pub(crate) fn inspect_text(session: &mut RedactionSession, text: &str) {
    if !session.admit_input(text.len()) {
        return;
    }
    if !admit_json_text_structure(session, text) {
        return;
    }
    let Ok(value) = from_str::<Value>(text) else {
        session.fail_inspection(RedactionReason::InvalidJson);
        return;
    };
    inspect_value(session, &value, true);
}

/// Classifies a parsed JSON subtree using the active base policy.
fn inspect_value(session: &mut RedactionSession, value: &Value, unkeyed: bool) {
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
