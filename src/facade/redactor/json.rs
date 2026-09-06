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

/// Writer that rejects the first byte beyond the final JSON byte budget.
struct BoundedJsonWriter {
    bytes: Vec<u8>,
    maximum: usize,
}

impl BoundedJsonWriter {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(maximum.min(4096)),
            maximum,
        }
    }
}

impl std::io::Write for BoundedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "redaction JSON output budget exceeded",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

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
        let mut writer = BoundedJsonWriter::new(self.policy().limits().max_output_bytes());
        serde_json::to_writer(&mut writer, &self.redact_view(value))?;
        String::from_utf8(writer.bytes)
            .map_err(|error| serde_json::Error::io(std::io::Error::new(std::io::ErrorKind::InvalidData, error)))
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
