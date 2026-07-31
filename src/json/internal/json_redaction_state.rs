// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Stateful bounded traversal for mutable JSON redaction.

use serde_json::Value;

use crate::{
    RedactionPolicy,
    Sensitivity,
};

use super::{
    JsonRedactionOutcome,
    JsonUnkeyedValuePolicy,
};

/// Mutable state shared by one JSON tree traversal.
pub(crate) struct JsonRedactionState<'policy, 'budget, 'marker> {
    /// Immutable field and masking policy.
    policy: &'policy RedactionPolicy,
    /// Handling for scalars without an object-key context.
    unkeyed: JsonUnkeyedValuePolicy<'marker>,
    /// Aggregate bytes remaining for newly generated masks.
    remaining_mask_bytes: &'budget mut usize,
}

impl<'policy, 'budget, 'marker> JsonRedactionState<'policy, 'budget, 'marker> {
    /// Creates traversal state for one JSON document.
    ///
    /// # Parameters
    ///
    /// * policy - Immutable policy used to classify object keys.
    /// * unkeyed - Handling selected for scalars without a key.
    /// * remaining_mask_bytes - Shared aggregate generated-mask budget.
    ///
    /// # Returns
    ///
    /// Mutable traversal state borrowing all operation inputs.
    #[inline(always)]
    pub(crate) const fn new(
        policy: &'policy RedactionPolicy,
        unkeyed: JsonUnkeyedValuePolicy<'marker>,
        remaining_mask_bytes: &'budget mut usize,
    ) -> Self {
        Self {
            policy,
            unkeyed,
            remaining_mask_bytes,
        }
    }

    /// Redacts one complete JSON tree.
    ///
    /// # Parameters
    ///
    /// * value - Tree mutated in place.
    ///
    /// # Returns
    ///
    /// The aggregate outcome for unkeyed scalar handling.
    pub(crate) fn redact(&mut self, value: &mut Value) -> JsonRedactionOutcome {
        self.redact_value(value, false, 0)
    }

    /// Redacts one JSON node with the enclosing key-context flag.
    ///
    /// # Parameters
    ///
    /// * value - Node mutated in place.
    /// * has_field - Whether an object key identifies this node.
    /// * depth - Recursive container depth measured from the root.
    ///
    /// # Returns
    ///
    /// The aggregate outcome for this node and its descendants.
    fn redact_value(
        &mut self,
        value: &mut Value,
        has_field: bool,
        depth: usize,
    ) -> JsonRedactionOutcome {
        if depth >= self.policy.json_depth_budget().max_depth()
            && matches!(value, Value::Object(_) | Value::Array(_))
        {
            self.mask_keyed_value(value, Sensitivity::Secret);
            return JsonRedactionOutcome::default();
        }
        match value {
            Value::Object(values) => self.redact_object(values, depth),
            Value::Array(values) => self.redact_array(values, has_field, depth),
            Value::Null
            | Value::Bool(_)
            | Value::Number(_)
            | Value::String(_) => self.redact_scalar(value, has_field),
        }
    }

    /// Redacts every keyed child in one JSON object.
    ///
    /// # Parameters
    ///
    /// * values - Object entries mutated in place.
    /// * depth - Current object depth measured from the root.
    ///
    /// # Returns
    ///
    /// Aggregate outcome for every traversed child.
    fn redact_object(
        &mut self,
        values: &mut serde_json::Map<String, Value>,
        depth: usize,
    ) -> JsonRedactionOutcome {
        let mut outcome = JsonRedactionOutcome::default();
        for (key, value) in values {
            if let Some(level) = self.policy.sensitivity_for(key) {
                self.mask_keyed_value(value, level);
            } else {
                outcome.merge(self.redact_value(
                    value,
                    true,
                    depth.saturating_add(1),
                ));
            }
        }
        outcome
    }

    /// Redacts every item in one JSON array.
    ///
    /// # Parameters
    ///
    /// * values - Array entries mutated in place.
    /// * has_field - Whether the enclosing object key identifies the array.
    /// * depth - Current array depth measured from the root.
    ///
    /// # Returns
    ///
    /// Aggregate outcome for every traversed item.
    fn redact_array(
        &mut self,
        values: &mut Vec<Value>,
        has_field: bool,
        depth: usize,
    ) -> JsonRedactionOutcome {
        let mut outcome = JsonRedactionOutcome::default();
        for value in values {
            outcome.merge(self.redact_value(
                value,
                has_field,
                depth.saturating_add(1),
            ));
        }
        outcome
    }

    /// Handles a JSON scalar according to its key context.
    ///
    /// # Parameters
    ///
    /// * value - Scalar potentially replaced by an unkeyed marker.
    /// * has_field - Whether an object key identifies the scalar.
    ///
    /// # Returns
    ///
    /// An outcome reporting a pass-through only for unkeyed visible scalars.
    fn redact_scalar(
        &mut self,
        value: &mut Value,
        has_field: bool,
    ) -> JsonRedactionOutcome {
        if has_field {
            return JsonRedactionOutcome::default();
        }
        match self.unkeyed {
            JsonUnkeyedValuePolicy::PassThrough => {
                JsonRedactionOutcome::passed_unkeyed()
            }
            JsonUnkeyedValuePolicy::Redact {
                marker,
                truncated_marker,
            } => {
                *value = Value::String(
                    self.take_unkeyed_marker(marker, truncated_marker),
                );
                JsonRedactionOutcome::default()
            }
        }
    }

    /// Replaces one keyed sensitive value with an appropriately bounded mask.
    ///
    /// # Parameters
    ///
    /// * value - Sensitive value replaced in place.
    /// * level - Sensitivity selecting the masking rule.
    fn mask_keyed_value(&mut self, value: &mut Value, level: Sensitivity) {
        let masked = match value {
            Value::String(text) => self
                .policy
                .masking()
                .mask_bounded(level, text, *self.remaining_mask_bytes)
                .into_owned(),
            _ => self
                .policy
                .masking()
                .mask_opaque_bounded(level, *self.remaining_mask_bytes),
        };
        *self.remaining_mask_bytes =
            self.remaining_mask_bytes.saturating_sub(masked.len());
        *value = Value::String(masked);
    }

    /// Consumes the remaining budget for one unkeyed marker.
    ///
    /// # Parameters
    ///
    /// * marker - Preferred marker.
    /// * truncated_marker - Shorter fallback marker.
    ///
    /// # Returns
    ///
    /// The preferred marker, fallback marker, or an empty replacement when no
    /// marker fits the remaining generated-mask budget.
    fn take_unkeyed_marker(
        &mut self,
        marker: &str,
        truncated_marker: &str,
    ) -> String {
        let selected = if *self.remaining_mask_bytes >= marker.len() {
            marker
        } else if *self.remaining_mask_bytes >= truncated_marker.len() {
            truncated_marker
        } else {
            return String::new();
        };
        *self.remaining_mask_bytes =
            self.remaining_mask_bytes.saturating_sub(selected.len());
        selected.to_owned()
    }
}
