// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Stateful JSON redaction after transaction-owned structural admission.

use serde_json::Value;

use super::JsonRedactionOutcome;
use super::JsonUnkeyedValuePolicy;
use crate::MaskingPolicy;
#[cfg(test)]
use crate::RedactionPolicy;
use crate::RedactionRules;
use crate::Sensitivity;
use crate::policy::ResolvedField;

/// Mutable state shared by one already-admitted JSON tree traversal.
pub(crate) struct JsonRedactionState<'policy, 'marker> {
    /// Immutable base field rules.
    base_rules: &'policy RedactionRules,
    /// Context-specific field enhancements.
    context_rules: &'policy RedactionRules,
    /// Single mask table used for every sensitivity level.
    masking: &'policy MaskingPolicy,
    /// Handling for scalars without an object-key context.
    unkeyed: JsonUnkeyedValuePolicy<'marker>,
    /// Whether an unkeyed scalar remained visible during traversal.
    passed_unkeyed: bool,
}

impl<'policy, 'marker> JsonRedactionState<'policy, 'marker> {
    /// Creates traversal state for one JSON document.
    #[inline(always)]
    pub(crate) const fn new(
        base_rules: &'policy RedactionRules,
        context_rules: &'policy RedactionRules,
        masking: &'policy MaskingPolicy,
        unkeyed: JsonUnkeyedValuePolicy<'marker>,
    ) -> Self {
        Self {
            base_rules,
            context_rules,
            masking,
            unkeyed,
            passed_unkeyed: false,
        }
    }

    /// Creates traversal state from one complete policy snapshot.
    #[cfg(test)]
    #[inline(always)]
    pub(crate) fn from_policy(
        policy: &'policy RedactionPolicy,
        unkeyed: JsonUnkeyedValuePolicy<'marker>,
    ) -> Self {
        Self::new(policy.rules(), policy.rules(), policy.masking(), unkeyed)
    }

    /// Redacts one complete tree whose nodes, collections, and depth were
    /// already admitted by the owning transaction.
    pub(crate) fn redact(&mut self, value: &mut Value) -> JsonRedactionOutcome {
        self.passed_unkeyed = false;
        self.redact_unkeyed(value);
        JsonRedactionOutcome::Complete {
            passed_unkeyed: self.passed_unkeyed,
        }
    }

    /// Redacts a root or array value.
    fn redact_unkeyed(&mut self, value: &mut Value) {
        match value {
            Value::Array(values) => {
                for value in values {
                    self.redact_unkeyed(value);
                }
            }
            Value::Object(entries) => {
                for (key, value) in entries {
                    self.redact_keyed(key, value);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                self.redact_unkeyed_scalar(value);
            }
        }
    }

    /// Applies the resolved rule to one object value.
    fn redact_keyed(&mut self, key: &str, value: &mut Value) {
        match self.resolve_field(key) {
            ResolvedField::Sensitive { sensitivity } => self.mask_keyed_value(value, sensitivity),
            ResolvedField::PassThrough => match value {
                Value::Array(values) => {
                    for value in values {
                        self.redact_unkeyed(value);
                    }
                }
                Value::Object(entries) => {
                    for (key, value) in entries {
                        self.redact_keyed(key, value);
                    }
                }
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
            },
        }
    }

    /// Applies the configured policy to one root or array scalar.
    fn redact_unkeyed_scalar(&mut self, value: &mut Value) {
        match self.unkeyed {
            JsonUnkeyedValuePolicy::PassThrough => self.passed_unkeyed = true,
            JsonUnkeyedValuePolicy::Redact { marker, .. } => {
                *value = Value::String(marker.to_owned());
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

    /// Replaces one keyed sensitive value with its configured mask.
    fn mask_keyed_value(&self, value: &mut Value, level: Sensitivity) {
        let masked = if let Value::String(text) = value {
            self.masking.mask(level, text).into_owned()
        } else {
            self.masking.mask_opaque(level).to_owned()
        };
        *value = Value::String(masked);
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
        (ResolvedField::Sensitive { sensitivity }, ResolvedField::PassThrough)
        | (ResolvedField::PassThrough, ResolvedField::Sensitive { sensitivity }) => {
            ResolvedField::Sensitive { sensitivity }
        }
        (ResolvedField::PassThrough, ResolvedField::PassThrough) => ResolvedField::PassThrough,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::JsonRedactionOutcome;
    use super::JsonRedactionState;
    use super::JsonUnkeyedValuePolicy;
    use crate::RedactionPolicy;
    use crate::Sensitivity;

    #[test]
    fn sensitive_non_string_value_is_replaced_by_an_opaque_mask() {
        let policy = RedactionPolicy::builder()
            .fields(|fields| {
                fields.sensitive(Sensitivity::Secret, "password");
            })
            .expect("test rules should build")
            .build()
            .expect("test policy should build");
        let mut value = json!({"password": {"nested": "raw-secret"}});
        let mut state =
            JsonRedactionState::from_policy(&policy, JsonUnkeyedValuePolicy::PassThrough);

        let outcome = state.redact(&mut value);

        assert!(matches!(outcome, JsonRedactionOutcome::Complete { .. }));
        assert_ne!(value["password"], json!({"nested": "raw-secret"}));
        assert!(value["password"].is_string());
    }

    #[test]
    fn context_rules_do_not_weaken_a_base_sensitive_rule() {
        let base = RedactionPolicy::builder()
            .fields(|fields| {
                fields.sensitive(Sensitivity::Secret, "credential");
            })
            .expect("base rules should build")
            .build()
            .expect("base policy should build");
        let context = RedactionPolicy::standard();
        let mut value = json!({"credential": "raw-secret"});
        let mut state = JsonRedactionState::new(
            base.rules(),
            context.rules(),
            base.masking(),
            JsonUnkeyedValuePolicy::PassThrough,
        );

        let outcome = state.redact(&mut value);

        assert!(matches!(outcome, JsonRedactionOutcome::Complete { .. }));
        assert!(!value.to_string().contains("raw-secret"));
        assert!(value["credential"].is_string());
    }
}
