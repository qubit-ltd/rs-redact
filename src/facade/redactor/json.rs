// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! JSON redaction operations.

use super::Redactor;
use crate::RedactionInspection;
use crate::RedactionInspectionError;
use crate::RedactionTextOutput;

impl Redactor {
    /// Serializes a domain object's redacted view as compact JSON.
    ///
    /// This uses domain field declarations, unlike `redact_json`, which parses
    /// input JSON and classifies its keys. It is equivalent to
    /// `serde_json::to_string(&self.redact_view(value))`. The value's fields
    /// must support the view's generated redacted serialization.
    ///
    /// # Errors
    ///
    /// Propagates JSON serializer errors and errors from the structured
    /// redaction budget. Successful serialization can contain the structured
    /// runtime's opaque replacements; it is not a completeness assertion.
    pub fn to_json<'value, T: crate::domain::internal::RedactSerializeSource + ?Sized>(
        &self,
        value: &'value T,
    ) -> Result<String, serde_json::Error>
    where
        T::RedactedFields<'value>: serde::Serialize,
    {
        serde_json::to_string(&self.redact_view(value))
    }

    /// Redacts JSON text through one completed text transaction.
    #[must_use]
    pub fn redact_json(&self, text: &str) -> RedactionTextOutput {
        let mut session = self.text_runtime();
        session.json(|json| {
            let _ = json.text(text);
        });
        session.finish()
    }

    /// Redacts a borrowed parsed JSON value without taking ownership of it.
    #[must_use]
    pub fn redact_json_value(&self, value: &serde_json::Value) -> RedactionTextOutput {
        let mut session = self.text_runtime();
        session.json(|json| {
            let _ = json.value(value);
        });
        session.finish()
    }

    /// Inspects one JSON document without rendering it.
    ///
    /// # Errors
    ///
    /// Returns [`RedactionInspectionError`] when JSON parsing fails or a
    /// shared resource limit prevents complete inspection.
    pub fn inspect_json(&self, text: &str) -> Result<RedactionInspection, RedactionInspectionError> {
        let mut session = self.inspection_runtime();
        crate::formats::json::inspection::inspect_text(&mut session, text);
        session.finish()
    }

    /// Inspects a borrowed parsed JSON value without taking ownership of it.
    ///
    /// # Errors
    ///
    /// Returns [`RedactionInspectionError`] when a shared structural, value,
    /// or input limit prevents complete inspection.
    pub fn inspect_json_value(
        &self,
        value: &serde_json::Value,
    ) -> Result<RedactionInspection, RedactionInspectionError> {
        let mut session = self.inspection_runtime();
        crate::formats::json::inspection::inspect_borrowed_value(&mut session, value);
        session.finish()
    }
}
