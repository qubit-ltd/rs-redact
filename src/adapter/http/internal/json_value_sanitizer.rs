// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Private JSON value sanitization.

use serde_json::Value;

use crate::{
    FieldSanitizer,
    NameMatchMode,
};

use super::super::{
    UnkeyedJsonValuePolicy,
    redaction_markers::UNKEYED_JSON_VALUE_REDACTED,
};

/// Applies field and unkeyed-value policies to a JSON value tree.
#[must_use = "the sanitizer must be used to sanitize a JSON value"]
pub(in crate::adapter::http) struct JsonValueSanitizer<'a> {
    /// Core sanitizer used for JSON object fields.
    field_sanitizer: &'a FieldSanitizer,
    /// Field-name matching mode for JSON object keys.
    match_mode: NameMatchMode,
    /// Policy for scalar values without an object-field context.
    unkeyed_value_policy: UnkeyedJsonValuePolicy,
}

impl<'a> JsonValueSanitizer<'a> {
    /// Creates a JSON value sanitizer.
    ///
    /// # Parameters
    ///
    /// * `field_sanitizer` - Core sanitizer used for JSON object fields.
    /// * `match_mode` - Field-name matching mode for JSON object keys.
    /// * `unkeyed_value_policy` - Policy for scalar values without an object
    ///   key.
    ///
    /// # Returns
    ///
    /// A sanitizer configured for one JSON or NDJSON operation.
    #[inline(always)]
    pub(in crate::adapter::http) const fn new(
        field_sanitizer: &'a FieldSanitizer,
        match_mode: NameMatchMode,
        unkeyed_value_policy: UnkeyedJsonValuePolicy,
    ) -> Self {
        Self {
            field_sanitizer,
            match_mode,
            unkeyed_value_policy,
        }
    }

    /// Sanitizes a JSON value tree in place.
    ///
    /// # Parameters
    ///
    /// * `value` - JSON value tree to sanitize.
    ///
    /// # Returns
    ///
    /// `true` when policy allowed at least one unkeyed scalar value unchanged.
    #[must_use]
    #[inline(always)]
    pub(in crate::adapter::http) fn sanitize(&self, value: &mut Value) -> bool {
        self.sanitize_with_context(value, false)
    }

    /// Sanitizes a JSON value while tracking its object-field context.
    ///
    /// # Parameters
    ///
    /// * `value` - JSON value to mutate.
    /// * `has_field_context` - Whether an enclosing object key identifies this
    ///   value.
    ///
    /// # Returns
    ///
    /// `true` when policy allowed at least one unkeyed scalar value unchanged.
    #[must_use]
    fn sanitize_with_context(
        &self,
        value: &mut Value,
        has_field_context: bool,
    ) -> bool {
        match value {
            Value::Object(map) => {
                let mut contains_passed_through_value = false;
                for (key, value) in map.iter_mut() {
                    if let Some(masked) = self.mask_field_value(key, value) {
                        *value = Value::String(masked);
                    } else {
                        contains_passed_through_value |=
                            self.sanitize_with_context(value, true);
                    }
                }
                contains_passed_through_value
            }
            Value::Array(items) => {
                let mut contains_passed_through_value = false;
                for item in items {
                    contains_passed_through_value |=
                        self.sanitize_with_context(item, has_field_context);
                }
                contains_passed_through_value
            }
            Value::Null
            | Value::Bool(_)
            | Value::Number(_)
            | Value::String(_) => {
                if has_field_context {
                    return false;
                }
                match self.unkeyed_value_policy {
                    UnkeyedJsonValuePolicy::Redact => {
                        *value = Value::String(
                            UNKEYED_JSON_VALUE_REDACTED.to_string(),
                        );
                        false
                    }
                    UnkeyedJsonValuePolicy::PassThrough => true,
                }
            }
        }
    }

    /// Masks a sensitive JSON object-field value.
    ///
    /// # Parameters
    ///
    /// * `field` - JSON object key used for sensitivity lookup.
    /// * `value` - JSON value to mask when the key is sensitive.
    ///
    /// # Returns
    ///
    /// `Some(masked)` when `field` is sensitive, otherwise `None`.
    #[inline]
    fn mask_field_value(&self, field: &str, value: &Value) -> Option<String> {
        let level = self
            .field_sanitizer
            .sensitivity_for_name(field, self.match_mode)?;
        let policy = self
            .field_sanitizer
            .policy()
            .mask_policies()
            .for_level(level);
        if let Value::String(value) = value {
            return Some(policy.mask(value).into_owned());
        }
        if let Some(masked) = policy.value_independent_non_empty_mask() {
            return Some(masked.to_owned());
        }
        let serialized = value.to_string();
        Some(policy.mask(&serialized).into_owned())
    }
}
