// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Stateful bounded traversal for mutable JSON redaction.

use qubit_budget::BudgetError;
use qubit_budget::ResourceBudget;
use qubit_budget::ResourceLimit;
use qubit_budget::StructureLimits;
use qubit_json::JsonResource;
use qubit_json::JsonValueBudget;
use qubit_json::JsonValueLimits;
use serde_json::Map;
use serde_json::Value;

use super::JsonRedactionOutcome;
use super::JsonUnkeyedValuePolicy;
use crate::JsonDepthLimit;
use crate::MaskingPolicy;
use crate::RedactionPolicy;
use crate::RedactionRules;
use crate::Sensitivity;
use crate::policy::RedactionResource;
use crate::policy::ResolvedField;

/// Mutable state shared by one JSON tree traversal.
pub(crate) struct JsonRedactionState<'policy, 'budget, 'marker> {
    /// Immutable base field rules.
    base_rules: &'policy RedactionRules,
    /// Context-specific field enhancements.
    context_rules: &'policy RedactionRules,
    /// Single mask table used for every sensitivity level.
    masking: &'policy MaskingPolicy,
    /// JSON structure accounting for the operation boundary.
    json_budget: JsonValueBudget<JsonResource, usize>,
    /// Handling for scalars without an object-key context.
    unkeyed: JsonUnkeyedValuePolicy<'marker>,
    /// Aggregate accounting for newly generated masks.
    mask_budget: Option<&'budget mut ResourceBudget<RedactionResource, usize>>,
}

impl<'policy, 'budget, 'marker> JsonRedactionState<'policy, 'budget, 'marker> {
    /// Creates traversal state for one JSON document.
    ///
    /// # Parameters
    ///
    /// * rules - Immutable field rules used to classify object keys.
    /// * json_depth_limit - Maximum recursive container depth.
    /// * unkeyed - Handling selected for scalars without a key.
    /// * mask_budget - Shared aggregate generated-mask accounting.
    ///
    /// # Returns
    ///
    /// Mutable traversal state borrowing all operation inputs.
    #[inline(always)]
    pub(crate) fn new(
        base_rules: &'policy RedactionRules,
        context_rules: &'policy RedactionRules,
        masking: &'policy MaskingPolicy,
        json_depth_limit: JsonDepthLimit,
        unkeyed: JsonUnkeyedValuePolicy<'marker>,
        mask_budget: Option<
            &'budget mut ResourceBudget<RedactionResource, usize>,
        >,
    ) -> Self {
        Self {
            base_rules,
            context_rules,
            masking,
            json_budget: JsonValueBudget::new(
                JsonValueLimits::<JsonResource, usize>::default()
                    .with_structure_limits(
                        StructureLimits::<JsonResource, usize>::empty()
                            .with_depth_limit(ResourceLimit::new(
                                JsonResource::Depth,
                                json_depth_limit.maximum(),
                            )),
                    ),
            ),
            unkeyed,
            mask_budget,
        }
    }

    /// Creates traversal state from one complete policy snapshot.
    #[inline(always)]
    pub(crate) fn from_policy(
        policy: &'policy RedactionPolicy,
        unkeyed: JsonUnkeyedValuePolicy<'marker>,
        mask_budget: Option<
            &'budget mut ResourceBudget<RedactionResource, usize>,
        >,
    ) -> Self {
        Self::new(
            policy.rules(),
            policy.rules(),
            policy.masking(),
            policy.json_depth_limit(),
            unkeyed,
            mask_budget,
        )
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
        let admission = match value {
            Value::Object(values) => self
                .json_budget
                .enter_object(depth.saturating_add(1), values.len()),
            Value::Array(values) => self
                .json_budget
                .enter_array(depth.saturating_add(1), values.len()),
            _ => self.json_budget.enter_node(depth.saturating_add(1)),
        };
        if matches!(
            admission,
            Err(BudgetError::LimitExceeded {
                resource: JsonResource::Depth,
                ..
            })
        ) && matches!(value, Value::Object(_) | Value::Array(_))
        {
            self.mask_keyed_value(value, Sensitivity::Secret);
            return JsonRedactionOutcome::default();
        }
        match value {
            Value::Object(values) => self.redact_object(values, depth),
            Value::Array(values) => self.redact_array(values, has_field, depth),
            Value::String(text) => {
                let _ = self.json_budget.consume_string_bytes(text.len());
                self.redact_scalar(value, has_field)
            }
            Value::Number(number) => {
                if self.json_budget.limits().number_bytes_limit().is_some()
                    || self.json_budget.limits().payload_bytes_limit().is_some()
                {
                    let _ = self
                        .json_budget
                        .consume_number_bytes(number.to_string().len());
                }
                self.redact_scalar(value, has_field)
            }
            Value::Null | Value::Bool(_) => {
                self.redact_scalar(value, has_field)
            }
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
        values: &mut Map<String, Value>,
        depth: usize,
    ) -> JsonRedactionOutcome {
        let mut outcome = JsonRedactionOutcome::default();
        for (key, value) in values {
            let _ = self.json_budget.consume_key_bytes(key.len());
            let resolved = stronger(
                self.base_rules.resolve_field(key),
                self.context_rules.resolve_field(key),
            );
            match resolved {
                ResolvedField::Sensitive { sensitivity } => {
                    self.mask_keyed_value(value, sensitivity);
                }
                ResolvedField::PassThrough => {
                    outcome.merge(self.redact_value(
                        value,
                        true,
                        depth.saturating_add(1),
                    ));
                }
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
        let remaining = self.remaining_mask_bytes();
        let masked = match value {
            Value::String(text) => self
                .masking
                .mask_bounded(level, text, remaining)
                .into_owned(),
            _ => self.masking.mask_opaque_bounded(level, remaining),
        };
        let consumed = self.consume_mask_available(masked.len());
        debug_assert_eq!(consumed, masked.len());
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
        let selected = if self.mask_available(marker.len()) {
            marker
        } else if self.mask_available(truncated_marker.len()) {
            truncated_marker
        } else {
            return String::new();
        };
        self.consume_mask(selected.len());
        selected.to_owned()
    }

    /// Returns the configured mask balance or an effectively unbounded value
    /// when this transformation has no mask budget.
    fn remaining_mask_bytes(&self) -> usize {
        self.mask_budget
            .as_deref()
            .map(|budget| budget.remaining())
            .unwrap_or(usize::MAX)
    }

    /// Checks whether a complete generated mask fits the configured budget.
    fn mask_available(&self, bytes: usize) -> bool {
        self.mask_budget
            .as_deref()
            .is_none_or(|budget| budget.check_available(bytes).is_ok())
    }

    /// Consumes a complete preauthorized generated mask when configured.
    fn consume_mask(&mut self, bytes: usize) {
        if let Some(budget) = self.mask_budget.as_deref_mut() {
            budget
                .try_consume(bytes)
                .expect("a preauthorized mask must remain consumable");
        }
    }

    /// Consumes the available portion of one bounded generated mask.
    fn consume_mask_available(&mut self, requested: usize) -> usize {
        self.mask_budget
            .as_deref_mut()
            .map_or(requested, |budget| budget.consume_available(requested))
    }
}

/// Combines the base policy and a context enhancement monotonically.
fn stronger(base: ResolvedField, context: ResolvedField) -> ResolvedField {
    match (base, context) {
        (
            ResolvedField::Sensitive { sensitivity: base },
            ResolvedField::Sensitive {
                sensitivity: context,
            },
        ) => ResolvedField::Sensitive {
            sensitivity: base.max(context),
        },
        (
            ResolvedField::Sensitive { sensitivity },
            ResolvedField::PassThrough,
        )
        | (
            ResolvedField::PassThrough,
            ResolvedField::Sensitive { sensitivity },
        ) => ResolvedField::Sensitive { sensitivity },
        (ResolvedField::PassThrough, ResolvedField::PassThrough) => {
            ResolvedField::PassThrough
        }
    }
}
