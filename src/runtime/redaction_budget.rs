// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable limits owned by one active redaction transaction.

#[cfg(feature = "json")]
use qubit_budget::json::JsonMeasurement;
#[cfg(feature = "json")]
use qubit_budget::json::JsonValueBudget;
#[cfg(feature = "json")]
use serde_json::Value;

use crate::RedactionLimits;
use crate::domain::internal::DomainRedactionContext;

/// The single mutable budget ledger for an active transaction.
pub(super) struct RedactionBudget {
    output_limit: usize,
    domain_context: DomainRedactionContext,
    #[cfg(feature = "json")]
    json_budget: JsonValueBudget,
}

impl RedactionBudget {
    /// Creates the budget from the immutable policy limits.
    #[must_use]
    pub(super) fn new(limits: &RedactionLimits) -> Self {
        Self {
            output_limit: limits.max_output_bytes(),
            domain_context: DomainRedactionContext::new(limits.domain()),
            #[cfg(feature = "json")]
            json_budget: limits.json().budget(),
        }
    }

    /// Returns the transaction-wide output ceiling.
    #[must_use]
    pub(super) const fn output_limit(&self) -> usize {
        self.output_limit
    }

    pub(super) fn domain_context(&mut self) -> &mut DomainRedactionContext {
        &mut self.domain_context
    }

    /// Borrows the structural ledger for non-mutating admission queries.
    pub(super) const fn domain_context_ref(&self) -> &DomainRedactionContext {
        &self.domain_context
    }

    #[cfg(feature = "json")]
    pub(super) fn admit_json_value(&mut self, root: &Value) -> bool {
        let mut transaction = self.json_budget.transaction();
        let mut pending = vec![(root, 1usize, None::<&str>)];
        while let Some((value, depth, key)) = pending.pop() {
            if let Some(key) = key
                && transaction
                    .try_admit(JsonMeasurement::Key { bytes: key.len() })
                    .is_err()
            {
                return false;
            }
            let measurement = match value {
                Value::Null => JsonMeasurement::Null { depth },
                Value::Bool(_) => JsonMeasurement::Boolean { depth },
                Value::Number(number) => JsonMeasurement::Number {
                    depth,
                    bytes: number.as_str().len(),
                },
                Value::String(text) => JsonMeasurement::String {
                    depth,
                    bytes: text.len(),
                },
                Value::Array(values) => JsonMeasurement::Array {
                    depth,
                    items: values.len(),
                },
                Value::Object(entries) => JsonMeasurement::Object {
                    depth,
                    entries: entries.len(),
                },
            };
            if transaction.try_admit(measurement).is_err() {
                return false;
            }
            match value {
                Value::Array(values) => {
                    for value in values.iter().rev() {
                        pending.push((value, depth.saturating_add(1), None));
                    }
                }
                Value::Object(entries) => {
                    for (key, value) in entries.iter().rev() {
                        pending.push((value, depth.saturating_add(1), Some(key.as_str())));
                    }
                }
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
            }
        }
        transaction.commit();
        true
    }
}
