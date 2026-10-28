// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Structured redaction capability for JSON text values.

use std::borrow::Cow;

#[cfg(feature = "json")]
use qubit_budget::json::JsonDecodeLimits;
#[cfg(feature = "json")]
use qubit_json::decode::JsonDecoder;
#[cfg(feature = "json")]
use qubit_json::value::DuplicateKeyRejectingJsonValue;
#[cfg(feature = "json")]
use qubit_json::value::traverse::JsonTreeBudgetTracker;
use serde::Serializer;
use serde_json::Value;

use super::json_value_admission::JsonValueAdmission as Admission;
use super::redact_serialize_scope::admit_collection_items;
use super::redact_serialize_scope::admit_input;
use super::redact_serialize_scope::admit_node;
use super::redact_serialize_scope::leave_node;
#[cfg(feature = "json")]
use super::redacted_json_serialize_ref::RedactedJsonSerializeRef;

/// Internal structured serialization capability for JSON text fields.
#[doc(hidden)]
#[cfg(feature = "json")]
pub trait RedactJsonSerialize {
    /// Parses and serializes JSON text through structured redaction.
    ///
    /// # Errors
    ///
    /// Propagates payload admission or downstream serialization failures.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the success and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted JSON representation.
    /// - `policy`: Immutable policy used for parsing limits and redaction.
    ///
    /// # Returns
    ///
    /// The destination result after all emitted data passes shared admission.
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: Serializer;
}

/// Parses and redacts one JSON text value for Serde publication.
///
/// # Errors
///
/// Returns a payload admission error or propagates the downstream serializer
/// error. Invalid or over-limit input is replaced with an opaque mask.
///
/// # Type Parameters
///
/// - `S`: Destination serializer.
///
/// # Parameters
///
/// - `serializer`: Destination receiving redacted JSON text or a safe mask.
/// - `text`: Raw JSON source admitted before parsing.
/// - `policy`: Immutable parsing, masking, and resource policy.
///
/// # Returns
///
/// The destination result for admitted transformed JSON text or the safe
/// replacement.
#[cfg(feature = "json")]
fn serialize_json_text<S>(serializer: S, text: &str, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let masked = || policy.masking().mask_opaque(crate::Sensitivity::Secret);
    if !admit_input(text.len()) {
        let replacement = masked();
        return super::redact_serialize_scope::serialize_payload(serializer, replacement);
    }
    if policy.is_disabled() {
        return super::redact_serialize_scope::serialize_payload(serializer, text);
    }
    if text.len() > policy.limits().max_input_bytes() {
        let replacement = masked();
        return super::redact_serialize_scope::serialize_payload(serializer, replacement);
    }
    let limits = JsonDecodeLimits::builder()
        .max_input_bytes(policy.limits().max_input_bytes())
        .value_limits(policy.limits().json_limits())
        .build();
    let Some(preflight) = super::redact_serialize_scope::json_preflight() else {
        let replacement = masked();
        return super::redact_serialize_scope::serialize_payload(serializer, replacement);
    };
    if preflight.validate(text).is_err() {
        let replacement = masked();
        return super::redact_serialize_scope::serialize_payload(serializer, replacement);
    }
    #[cfg(test)]
    crate::formats::json::parse_counter::record_json_materialization();
    let Ok(value) = JsonDecoder::with_limits(limits).decode_unique_str::<DuplicateKeyRejectingJsonValue>(text) else {
        let replacement = masked();
        return super::redact_serialize_scope::serialize_payload(serializer, replacement);
    };
    let value = value.into_inner();
    if !admit_structured_json_value(&value) {
        let replacement = masked();
        return super::redact_serialize_scope::serialize_payload(serializer, replacement);
    }
    let output = crate::formats::json::redact_json_value_with_limit(
        policy,
        &value,
        super::redact_serialize_scope::remaining_payload_bytes(),
    );
    super::redact_serialize_scope::serialize_payload(serializer, output.text())
}

/// Admits every node and item in a parsed JSON value.
///
/// # Parameters
///
/// - `value`: Parsed JSON whose nodes and collection entries share the active
///   scope.
///
/// # Returns
///
/// True when every node and item is admitted; false on structural rejection.
/// All entered depth frames are left before returning in either case.
#[cfg(feature = "json")]
fn admit_structured_json_value(value: &Value) -> bool {
    let mut pending = vec![Admission::Enter(value)];
    let mut entered = 0_usize;
    while let Some(admission) = pending.pop() {
        match admission {
            Admission::Enter(value) => {
                if !admit_node() {
                    while entered > 0 {
                        leave_node();
                        entered -= 1;
                    }
                    return false;
                }
                entered += 1;
                pending.push(Admission::Leave);
                match value {
                    Value::Array(values) => {
                        pending.extend(values.iter().rev().map(Admission::Child));
                    }
                    Value::Object(entries) => {
                        pending.extend(entries.values().rev().map(Admission::Child));
                    }
                    Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
                }
            }
            Admission::Child(value) => {
                if !admit_collection_items(1) {
                    while entered > 0 {
                        leave_node();
                        entered -= 1;
                    }
                    return false;
                }
                pending.push(Admission::Enter(value));
            }
            Admission::Leave => {
                leave_node();
                entered -= 1;
            }
        }
    }
    true
}

#[cfg(all(test, feature = "json"))]
mod tests {
    use serde_json::to_value;

    use super::RedactedJsonSerializeRef;
    use super::serialize_json_text;
    use crate::RedactionPolicy;
    use crate::domain::internal::redact_serialize_scope::RedactSerializeScope;
    use crate::formats::json::parse_counter::json_materialization_count;
    use crate::formats::json::parse_counter::reset_json_materialization_count;

    #[test]
    fn test_preflight_serde_masks_before_entering_unique_decoder() {
        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_nodes(1).max_input_bytes(1_000_000);
            })
            .expect("limits")
            .build()
            .expect("policy");
        let source = format!("[{}]", "0,".repeat(10_000) + "0");

        reset_json_materialization_count();
        let output =
            to_value(RedactedJsonSerializeRef::new(source.as_str(), &policy)).expect("opaque replacement serializes");

        assert_eq!(output, "<redacted>");
        assert_eq!(json_materialization_count(), 0);
    }

    #[test]
    fn test_serde_preflight_rejection_does_not_poison_active_scope() {
        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_nodes(1).max_input_bytes(1_000_000);
            })
            .expect("limits")
            .build()
            .expect("policy");
        let source = format!("[{}]", "0,".repeat(10_000) + "0");
        let _scope = RedactSerializeScope::new(&policy);
        reset_json_materialization_count();

        let rejected = serialize_json_text(serde_json::value::Serializer, &source, &policy)
            .expect("opaque replacement serializes");
        let accepted =
            serialize_json_text(serde_json::value::Serializer, "0", &policy).expect("subsequent scalar serializes");

        assert_eq!(rejected, "<redacted>");
        assert_eq!(accepted, "0");
        assert_eq!(json_materialization_count(), 1);
    }
}

#[cfg(feature = "json")]
impl RedactJsonSerialize for String {
    /// Delegates JSON representation through the active policy and shared
    /// scope.
    ///
    /// # Errors
    ///
    /// Propagates budget or downstream serialization failures.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the success and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted JSON representation.
    /// - `policy`: Immutable policy used for parsing limits and redaction.
    ///
    /// # Returns
    ///
    /// The destination result after all emitted data passes shared admission.
    #[inline(always)]
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_json_text(serializer, self.as_str(), policy)
    }
}

#[cfg(feature = "json")]
impl RedactJsonSerialize for str {
    /// Delegates JSON representation through the active policy and shared
    /// scope.
    ///
    /// # Errors
    ///
    /// Propagates budget or downstream serialization failures.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the success and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted JSON representation.
    /// - `policy`: Immutable policy used for parsing limits and redaction.
    ///
    /// # Returns
    ///
    /// The destination result after all emitted data passes shared admission.
    #[inline(always)]
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_json_text(serializer, self, policy)
    }
}

impl RedactJsonSerialize for Cow<'_, str> {
    /// Delegates JSON representation through the active policy and shared
    /// scope.
    ///
    /// # Errors
    ///
    /// Propagates budget or downstream serialization failures.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the success and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted JSON representation.
    /// - `policy`: Immutable policy used for parsing limits and redaction.
    ///
    /// # Returns
    ///
    /// The destination result after all emitted data passes shared admission.
    #[inline(always)]
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_json_text(serializer, self.as_ref(), policy)
    }
}

impl<T: RedactJsonSerialize + ?Sized> RedactJsonSerialize for &T {
    /// Delegates JSON representation through the active policy and shared
    /// scope.
    ///
    /// # Errors
    ///
    /// Propagates budget or downstream serialization failures.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the success and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted JSON representation.
    /// - `policy`: Immutable policy used for parsing limits and redaction.
    ///
    /// # Returns
    ///
    /// The destination result after all emitted data passes shared admission.
    #[inline(always)]
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (*self).serialize_redacted_json(serializer, policy)
    }
}

impl<T: RedactJsonSerialize> RedactJsonSerialize for Option<T> {
    /// Delegates JSON representation through the active policy and shared
    /// scope.
    ///
    /// # Errors
    ///
    /// Propagates budget or downstream serialization failures.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the success and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted JSON representation.
    /// - `policy`: Immutable policy used for parsing limits and redaction.
    ///
    /// # Returns
    ///
    /// The destination result after all emitted data passes shared admission.
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Some(value) => serializer.serialize_some(&RedactedJsonSerializeRef::new(value, policy)),
            None => serializer.serialize_none(),
        }
    }
}

impl RedactJsonSerialize for Value {
    /// Checks JSON-specific limits for this complete value before serialization.
    ///
    /// Each Value field is checked independently against the policy's JSON
    /// limits. When enabled redaction rejects any part of the tree, the whole
    /// field is replaced with the configured Secret opaque mask. The replacement
    /// still passes through the active shared Serde scope and destination
    /// serializer. Disabled policies skip only this JSON-specific check.
    ///
    /// # Errors
    ///
    /// Propagates budget or downstream serialization failures.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the success and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted JSON representation.
    /// - `policy`: Immutable policy used for parsing limits and redaction.
    ///
    /// # Returns
    ///
    /// The destination result after all emitted data passes shared admission.
    #[inline(always)]
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[cfg(feature = "json")]
        if !policy.is_disabled()
            && JsonTreeBudgetTracker::new(policy.limits().json_limits())
                .account(self)
                .is_err()
        {
            return super::redact_serialize_scope::serialize_payload(
                serializer,
                policy.masking().mask_opaque(crate::Sensitivity::Secret),
            );
        }
        crate::formats::json::serialize_redacted_value(self, serializer, policy)
    }
}
