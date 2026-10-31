// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed JSON value serialized under one redaction state.

use serde::Serialize;
use serde::Serializer;
use serde::ser::SerializeMap;
use serde::ser::SerializeSeq;
use serde_json::Value;

use super::JsonRedactionState;
use super::value_context::ValueContext;
use crate::Sensitivity;
use crate::policy::ResolvedField;

/// Couples a borrowed JSON value with the state and context governing it.
pub(crate) struct RedactedValue<'value, 'policy, 'marker, 'state> {
    /// Source value serialized without cloning or reparsing.
    value: &'value Value,
    /// Rules, masks, and observation state shared by this traversal.
    state: &'state JsonRedactionState<'policy, 'marker>,
    /// Rule context inherited from the containing JSON object, if any.
    context: ValueContext,
}

impl<'value, 'policy, 'marker, 'state> RedactedValue<'value, 'policy, 'marker, 'state> {
    /// Creates a root value with no enclosing field rule.
    #[must_use]
    #[inline]
    pub(in crate::formats::json) const fn with_state(
        value: &'value Value,
        state: &'state JsonRedactionState<'policy, 'marker>,
    ) -> Self {
        Self {
            value,
            state,
            context: ValueContext::Unkeyed,
        }
    }

    /// Creates a child value inheriting the active state and selected context.
    const fn child(
        value: &'value Value,
        state: &'state JsonRedactionState<'policy, 'marker>,
        context: ValueContext,
    ) -> Self {
        Self { value, state, context }
    }
}

impl Serialize for RedactedValue<'_, '_, '_, '_> {
    /// Serializes the value after applying the inherited JSON redaction rule.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !self.state.enabled {
            return self.value.serialize(serializer);
        }
        if let ValueContext::Keyed(level) = self.context {
            return self.serialize_masked(serializer, level);
        }
        match self.value {
            Value::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(&Self::child(value, self.state, ValueContext::Unkeyed))?;
                }
                sequence.end()
            }
            Value::Object(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    let base = self.state.base_rules.resolve_field(key);
                    let context = if std::ptr::eq(self.state.base_rules, self.state.context_rules) {
                        base
                    } else {
                        self.state.context_rules.resolve_field(key)
                    };
                    let context = match (base, context) {
                        (ResolvedField::Sensitive { sensitivity: base }, ResolvedField::Sensitive { sensitivity }) => {
                            ValueContext::Keyed(base.max(sensitivity))
                        }
                        (ResolvedField::Sensitive { sensitivity }, ResolvedField::PassThrough)
                        | (ResolvedField::PassThrough, ResolvedField::Sensitive { sensitivity }) => {
                            ValueContext::Keyed(sensitivity)
                        }
                        (ResolvedField::PassThrough, ResolvedField::PassThrough) => ValueContext::PassThrough,
                    };
                    map.serialize_entry(key, &Self::child(value, self.state, context))?;
                }
                map.end()
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
                if matches!(self.context, ValueContext::Unkeyed) =>
            {
                match self.state.unkeyed {
                    super::JsonUnkeyedValuePolicy::Redact { marker } => serializer.serialize_str(marker),
                    super::JsonUnkeyedValuePolicy::PassThrough => {
                        self.state.observe_unkeyed_passthrough();
                        self.value.serialize(serializer)
                    }
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => self.value.serialize(serializer),
        }
    }
}

impl RedactedValue<'_, '_, '_, '_> {
    fn serialize_masked<S: Serializer>(&self, serializer: S, level: Sensitivity) -> Result<S::Ok, S::Error> {
        let masking = self.state.masking.for_level(level);
        if let Value::String(text) = self.value {
            if text.is_empty() {
                return serializer.serialize_str("");
            }
            match masking {
                crate::MaskPolicy::Fixed { replacement } => serializer.serialize_str(replacement),
                crate::MaskPolicy::Empty => serializer.serialize_str(""),
                _ => serializer.collect_str(&super::MaskedJsonText::new(masking, text)),
            }
        } else {
            serializer.serialize_str(masking.opaque_mask())
        }
    }
}
