// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Stateful bounded traversal for mutable JSON redaction.

use qubit_budget::BudgetError;
use qubit_budget::MeasuredBudgetError;
use qubit_budget::ResourceBudget;
use qubit_budget::json::JsonResource;
use qubit_budget::json::JsonValueLimits;
use qubit_json::tree::JsonBudgetRejection;
use qubit_json::tree::JsonTreeContext;
use qubit_json::tree::JsonTreeControl;
use qubit_json::tree::JsonTreeLocation;
use qubit_json::tree::JsonTreeMutVisitor;
use qubit_json::tree::JsonTreeProcessError;
use qubit_json::tree::JsonTreeProcessor;
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

mod stop {
    /// Stops one mutable JSON traversal after the mask budget is exhausted.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct JsonRedactionStop;
}

use stop::JsonRedactionStop;

/// Mutable state shared by one JSON tree traversal.
pub(crate) struct JsonRedactionState<'policy, 'budget, 'marker> {
    /// Immutable base field rules.
    base_rules: &'policy RedactionRules,
    /// Context-specific field enhancements.
    context_rules: &'policy RedactionRules,
    /// Single mask table used for every sensitivity level.
    masking: &'policy MaskingPolicy,
    /// Maximum root-inclusive depth admitted by each traversal.
    json_depth_limit: JsonDepthLimit,
    /// Handling for scalars without an object-key context.
    unkeyed: JsonUnkeyedValuePolicy<'marker>,
    /// Aggregate accounting for newly generated masks.
    mask_budget: Option<&'budget mut ResourceBudget<RedactionResource, usize>>,
    /// Whether an unkeyed scalar remained visible during traversal.
    passed_unkeyed: bool,
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
            json_depth_limit,
            unkeyed,
            mask_budget,
            passed_unkeyed: false,
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
        self.passed_unkeyed = false;
        let mut budget = JsonValueLimits::empty()
            .with_max_depth(self.json_depth_limit.maximum())
            .budget();
        let mut transaction = budget.transaction();
        let result =
            JsonTreeProcessor::new(&mut transaction).process_mut(value, self);
        match result {
            Ok(()) => {
                transaction.commit();
                JsonRedactionOutcome::Complete {
                    passed_unkeyed: self.passed_unkeyed,
                }
            }
            Err(JsonTreeProcessError::Visitor(JsonRedactionStop)) => {
                JsonRedactionOutcome::MaskBudgetExhausted
            }
            Err(JsonTreeProcessError::Budget(error)) => {
                unreachable!(
                    "the redaction visitor handles every configured depth rejection: {error}"
                )
            }
        }
    }

    /// Applies field rules to one value associated with an object key.
    ///
    /// # Parameters
    ///
    /// * key - Object key used to resolve sensitivity.
    /// * value - Value potentially masked in place.
    ///
    /// # Returns
    ///
    /// Whether traversal should descend into the value. This function does not
    /// currently fail, but exposes the visitor stop type for a uniform policy
    /// interface.
    fn visit_keyed_value(
        &mut self,
        key: &str,
        value: &mut Value,
    ) -> Result<JsonTreeControl, JsonRedactionStop> {
        match self.resolve_field(key) {
            ResolvedField::Sensitive { sensitivity } => {
                self.mask_keyed_value(value, sensitivity);
                Ok(JsonTreeControl::SkipSubtree)
            }
            ResolvedField::PassThrough
                if matches!(value, Value::Object(_) | Value::Array(_)) =>
            {
                Ok(JsonTreeControl::Descend)
            }
            ResolvedField::PassThrough => Ok(JsonTreeControl::SkipSubtree),
        }
    }

    /// Applies unkeyed policy to one root or array value.
    ///
    /// # Parameters
    ///
    /// * value - Value potentially masked in place.
    ///
    /// # Returns
    ///
    /// Whether traversal should descend, or a stop signal when no unkeyed mask
    /// can fit the remaining mask budget.
    fn visit_unkeyed_value(
        &mut self,
        value: &mut Value,
    ) -> Result<JsonTreeControl, JsonRedactionStop> {
        if matches!(value, Value::Object(_) | Value::Array(_)) {
            Ok(JsonTreeControl::Descend)
        } else {
            self.redact_unkeyed_scalar(value)?;
            Ok(JsonTreeControl::SkipSubtree)
        }
    }

    /// Applies the configured policy to one root or array scalar.
    ///
    /// # Parameters
    ///
    /// * value - Scalar potentially replaced by a diagnostic marker.
    ///
    /// # Returns
    ///
    /// Returns `JsonRedactionStop` when neither configured marker fits the
    /// remaining mask budget.
    fn redact_unkeyed_scalar(
        &mut self,
        value: &mut Value,
    ) -> Result<(), JsonRedactionStop> {
        match self.unkeyed {
            JsonUnkeyedValuePolicy::PassThrough => {
                self.passed_unkeyed = true;
                Ok(())
            }
            JsonUnkeyedValuePolicy::Redact {
                marker,
                truncated_marker,
            } => match self.take_unkeyed_marker(marker, truncated_marker) {
                Some(marker) => {
                    *value = Value::String(marker);
                    Ok(())
                }
                None => Err(JsonRedactionStop),
            },
        }
    }

    /// Handles a node rejected by the operation-local JSON budget.
    ///
    /// Depth rejection follows the node's field or unkeyed policy. Any other
    /// rejection fails closed with an opaque secret mask.
    fn handle_budget_rejection(
        &mut self,
        value: &mut Value,
        context: JsonTreeContext<'_>,
        error: &MeasuredBudgetError<JsonResource, usize>,
    ) -> Result<(), JsonRedactionStop> {
        if !is_depth_rejection(error) {
            self.mask_opaque_value(value, Sensitivity::Secret);
            return Ok(());
        }
        match context.location {
            JsonTreeLocation::ObjectValue { key } => match self
                .resolve_field(key)
            {
                ResolvedField::Sensitive { sensitivity } => {
                    self.mask_keyed_value(value, sensitivity);
                    Ok(())
                }
                ResolvedField::PassThrough
                    if matches!(value, Value::Object(_) | Value::Array(_)) =>
                {
                    self.mask_opaque_value(value, Sensitivity::Secret);
                    Ok(())
                }
                ResolvedField::PassThrough => Ok(()),
            },
            JsonTreeLocation::Root | JsonTreeLocation::ArrayElement { .. }
                if matches!(value, Value::Object(_) | Value::Array(_)) =>
            {
                self.mask_opaque_value(value, Sensitivity::Secret);
                Ok(())
            }
            JsonTreeLocation::Root | JsonTreeLocation::ArrayElement { .. } => {
                self.redact_unkeyed_scalar(value)
            }
        }
    }

    /// Resolves one field against base and context rules monotonically.
    fn resolve_field(&self, key: &str) -> ResolvedField {
        stronger(
            self.base_rules.resolve_field(key),
            self.context_rules.resolve_field(key),
        )
    }

    /// Replaces one keyed sensitive value with an appropriately bounded mask.
    ///
    /// # Parameters
    ///
    /// * value - Sensitive value replaced in place.
    /// * level - Sensitivity selecting the masking rule.
    fn mask_keyed_value(&mut self, value: &mut Value, level: Sensitivity) {
        let remaining = self.remaining_mask_bytes();
        let masked = if let Value::String(text) = value {
            self.masking
                .mask_bounded(level, text, remaining)
                .into_owned()
        } else {
            self.masking.mask_opaque_bounded(level, remaining)
        };
        let consumed = self.consume_mask_available(masked.len());
        debug_assert_eq!(consumed, masked.len());
        if let Value::String(text) = value {
            *text = masked;
        } else {
            replace_value_iteratively(value, Value::String(masked));
        }
    }

    /// Replaces any JSON value with an opaque mask at the requested level.
    fn mask_opaque_value(&mut self, value: &mut Value, level: Sensitivity) {
        let masked = self
            .masking
            .mask_opaque_bounded(level, self.remaining_mask_bytes());
        let consumed = self.consume_mask_available(masked.len());
        debug_assert_eq!(consumed, masked.len());
        if let Value::String(text) = value {
            *text = masked;
        } else {
            replace_value_iteratively(value, Value::String(masked));
        }
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
    /// The preferred marker or fallback marker. Returns `None` when neither
    /// fits, so callers can use a non-allocating JSON null replacement.
    fn take_unkeyed_marker(
        &mut self,
        marker: &str,
        truncated_marker: &str,
    ) -> Option<String> {
        let selected = if self.mask_available(marker.len()) {
            marker
        } else if self.mask_available(truncated_marker.len()) {
            truncated_marker
        } else {
            return None;
        };
        self.consume_mask(selected.len());
        Some(selected.to_owned())
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

impl JsonTreeMutVisitor<JsonResource, usize>
    for JsonRedactionState<'_, '_, '_>
{
    type Error = JsonRedactionStop;

    /// Applies the current-node redaction policy and controls descent.
    fn visit(
        &mut self,
        value: &mut Value,
        context: JsonTreeContext<'_>,
    ) -> Result<JsonTreeControl, Self::Error> {
        match context.location {
            JsonTreeLocation::ObjectValue { key } => {
                self.visit_keyed_value(key, value)
            }
            JsonTreeLocation::Root | JsonTreeLocation::ArrayElement { .. } => {
                self.visit_unkeyed_value(value)
            }
        }
    }

    /// Fails closed for rejected nodes and always skips their subtrees.
    fn reject_budget(
        &mut self,
        value: &mut Value,
        context: JsonTreeContext<'_>,
        error: &MeasuredBudgetError<JsonResource, usize>,
    ) -> Result<JsonBudgetRejection, Self::Error> {
        self.handle_budget_rejection(value, context, error)?;
        Ok(JsonBudgetRejection::SkipSubtree)
    }
}

/// Reports whether the budget failure is the configured depth rejection.
fn is_depth_rejection(
    error: &MeasuredBudgetError<JsonResource, usize>,
) -> bool {
    matches!(
        error,
        MeasuredBudgetError::Budget(BudgetError::LimitExceeded {
            resource: JsonResource::Depth,
            ..
        })
    )
}

/// Replaces a JSON value and releases its former tree without recursive drop.
///
/// # Parameters
///
/// * value - JSON slot receiving the replacement.
/// * replacement - New value stored in the slot.
fn replace_value_iteratively(value: &mut Value, replacement: Value) {
    let original = std::mem::replace(value, replacement);
    drop_value_iteratively(original);
}

/// Releases a JSON value tree by emptying every container before it drops.
///
/// # Parameters
///
/// * root - Detached JSON tree to release.
fn drop_value_iteratively(root: Value) {
    let mut pending = vec![root];
    while let Some(mut value) = pending.pop() {
        match &mut value {
            Value::Array(values) => pending.append(values),
            Value::Object(entries) => {
                pending.extend(std::mem::take(entries).into_values())
            }
            Value::Null
            | Value::Bool(_)
            | Value::Number(_)
            | Value::String(_) => {}
        }
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
