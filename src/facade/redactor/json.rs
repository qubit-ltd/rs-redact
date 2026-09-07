// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! JSON redaction operations.

use std::io::Error as IoError;
use std::io::ErrorKind;

use serde::Serialize;
use serde_json::Error as JsonError;
use serde_json::Value;
use serde_json::to_writer;

use super::Redactor;
use super::internal::bounded_json_writer::BoundedJsonWriter;
use crate::RedactionInspection;
use crate::RedactionInspectionError;
use crate::RedactionTextOutput;

impl Redactor {
    /// Serializes a domain object's redacted view as compact JSON.
    ///
    /// This uses domain field declarations, unlike `redact_json`, which parses
    /// input JSON and classifies its keys. It shares the view's projection and
    /// logical Serde payload budget, and additionally bounds the final encoded
    /// JSON by `max_output_bytes`, including labels, framing, and escaping.
    /// Serialization runs once; no partial string is returned on failure.
    /// With identical source state, outputs match direct view serialization
    /// when both succeed. The view's fields must support redacted
    /// serialization.
    ///
    /// # Errors
    ///
    /// Propagates JSON serializer errors and errors from the structured
    /// redaction budget. Successful serialization can contain the structured
    /// runtime's opaque replacements; it is not a completeness assertion.
    ///
    /// # Type Parameters
    ///
    /// - `'value`: Source borrow retained while serializing the projection.
    /// - `T`: Possibly unsized source whose borrowed redacted fields implement
    ///   Serialize.
    ///
    /// # Parameters
    ///
    /// - `value`: Source borrowed and traversed once through its redacted
    ///   projection.
    ///
    /// # Returns
    ///
    /// A complete compact JSON string within the final encoded output limit.
    #[inline]
    pub fn to_json<'value, T: crate::domain::internal::RedactSerializeSource + ?Sized>(
        &self,
        value: &'value T,
    ) -> Result<String, JsonError>
    where
        T::RedactedFields<'value>: Serialize,
    {
        let mut writer = BoundedJsonWriter::new(self.policy().limits().max_output_bytes());
        to_writer(&mut writer, &self.redact_view(value))?;
        String::from_utf8(writer.into_bytes().map_err(JsonError::io)?)
            .map_err(|error| JsonError::io(IoError::new(ErrorKind::InvalidData, error)))
    }

    /// Redacts JSON text through one completed text transaction.
    ///
    /// # Parameters
    ///
    /// - `text`: Complete raw JSON input admitted before parsing.
    ///
    /// # Returns
    ///
    /// Safe bounded text and its completion, provenance, and resource
    /// accounting.
    #[must_use]
    #[inline]
    pub fn redact_json(&self, text: &str) -> RedactionTextOutput {
        let mut session = self.text_runtime();
        session.json(|json| {
            let _ = json.text(text);
        });
        session.finish()
    }

    /// Redacts a borrowed parsed JSON value without taking ownership of it.
    ///
    /// # Parameters
    ///
    /// - `value`: Borrowed parsed tree admitted under shared resource limits.
    ///
    /// # Returns
    ///
    /// Safe bounded text and its completion, provenance, and resource
    /// accounting.
    #[must_use]
    #[inline]
    pub fn redact_json_value(&self, value: &Value) -> RedactionTextOutput {
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
    ///
    /// # Parameters
    ///
    /// - `text`: Complete raw JSON input to classify without rendering values.
    ///
    /// # Returns
    ///
    /// A conclusive sensitivity observation when parsing and traversal
    /// complete.
    #[inline]
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
    ///
    /// # Parameters
    ///
    /// - `value`: Borrowed parsed tree to classify without rendering values.
    ///
    /// # Returns
    ///
    /// A conclusive sensitivity observation when the entire traversal is
    /// admitted.
    #[inline]
    pub fn inspect_json_value(&self, value: &Value) -> Result<RedactionInspection, RedactionInspectionError> {
        let mut session = self.inspection_runtime();
        crate::formats::json::inspection::inspect_borrowed_value(&mut session, value);
        session.finish()
    }
}
