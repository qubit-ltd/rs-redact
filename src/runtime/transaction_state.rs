// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unpublished mutable state owned by one redaction transaction.

#[cfg(feature = "json")]
use qubit_budget::json::JsonMeasurement;
#[cfg(feature = "json")]
use qubit_budget::json::JsonValueBudget;
#[cfg(feature = "json")]
use serde_json::Value;

use super::redaction_budget::RedactionBudget;
use crate::RedactionOutput;
use crate::RedactionPolicy;
use crate::RedactionSummary;
use crate::domain::internal::DomainRedactionContext;

/// All mutable accounting and unpublished output for one transaction.
#[derive(Debug)]
pub struct TransactionState {
    pub(super) id: u64,
    pub(super) budget: RedactionBudget,
    pub(super) domain_context: DomainRedactionContext,
    /// JSON-specific point and payload accounting owned by this transaction.
    #[cfg(feature = "json")]
    json_budget: JsonValueBudget,
    pub(super) fragments: String,
    pub(super) items: Vec<RedactionOutput>,
    pub(super) output_exhausted: bool,
    pub(super) summary: RedactionSummary,
    /// Summary accumulated only for the currently staged handle operation.
    pub(super) item_summary: Option<RedactionSummary>,
}

impl TransactionState {
    /// Creates an empty transaction governed by `policy`.
    #[must_use]
    pub(super) fn new(policy: &RedactionPolicy, id: u64) -> Self {
        Self {
            id,
            budget: RedactionBudget::new(policy.limits()),
            domain_context: DomainRedactionContext::new(policy.limits().domain()),
            #[cfg(feature = "json")]
            json_budget: policy.limits().json().budget(),
            fragments: String::new(),
            items: Vec::new(),
            output_exhausted: false,
            summary: RedactionSummary::complete(),
            item_summary: None,
        }
    }

    /// Admits one parsed JSON tree to this transaction's JSON-specific ledger.
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
