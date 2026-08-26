// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! JSON redaction operations.

use super::Redactor;
use crate::RedactionInspectionResult;
use crate::RedactionTextOutput;

impl Redactor {
    /// Redacts JSON text through one completed batch transaction.
    #[must_use]
    pub fn redact_json(&self, text: &str) -> RedactionTextOutput {
        let mut batch = self.batch();
        let handle = batch.redact_json(text);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Redacts a borrowed parsed JSON value without taking ownership of it.
    #[must_use]
    pub fn redact_json_value(&self, value: &serde_json::Value) -> RedactionTextOutput {
        let mut batch = self.batch();
        let handle = batch.redact_json_value(value);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Inspects one JSON document without rendering it.
    pub fn inspect_json(&self, text: &str) -> RedactionInspectionResult {
        let mut session = self.inspection_runtime();
        crate::formats::json::inspection::inspect_text(&mut session, text);
        session.finish()
    }

    /// Inspects a borrowed parsed JSON value without taking ownership of it.
    pub fn inspect_json_value(&self, value: &serde_json::Value) -> RedactionInspectionResult {
        let mut session = self.inspection_runtime();
        crate::formats::json::inspection::inspect_borrowed_value(&mut session, value);
        session.finish()
    }
}
