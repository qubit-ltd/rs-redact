// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Deterministic grouping for HTTP header rendering.

use std::collections::BTreeMap;

use http::HeaderMap;
use http::HeaderValue;
use qubit_budget::ResourceBudget;

use super::HttpRedactor;
use crate::Sensitivity;
use crate::formats::http::internal::BoundedLogWriter;
use crate::policy::RedactionResource;

/// Groups repeated header values under deterministically ordered names.
pub(super) fn group_values(
    headers: &HeaderMap,
) -> BTreeMap<&str, Vec<&HeaderValue>> {
    let mut values = BTreeMap::<&str, Vec<&HeaderValue>>::new();
    for (name, value) in headers {
        values.entry(name.as_str()).or_default().push(value);
    }
    values
}

/// Renders one header entry without inspecting any following entry.
pub(in crate::formats::http) fn render_one(
    redactor: &HttpRedactor,
    name: &str,
    value: &HeaderValue,
    max_output_bytes: usize,
) -> (String, bool) {
    let mut writer = BoundedLogWriter::new(max_output_bytes, false);
    let _ = writer.write_str(name);
    let _ = writer.write_str(": [");
    redactor.write_header_values(
        &mut writer,
        name,
        std::slice::from_ref(&value),
    );
    if !writer.is_full() {
        let _ = writer.write_str("]");
    }
    writer.finish()
}

impl HttpRedactor {
    /// Checks the complete header input against the diagnostic budget.
    pub(super) fn headers_fit_input_budget(&self, headers: &HeaderMap) -> bool {
        let mut input_budget = ResourceBudget::new(
            RedactionResource::Input,
            self.policy().limits().diagnostic_event().max_input_bytes(),
        );
        for (name, value) in headers {
            if input_budget.try_consume(name.as_str().len()).is_err()
                || input_budget.try_consume(value.as_bytes().len()).is_err()
            {
                return false;
            }
        }
        true
    }

    /// Writes deterministically grouped headers to a bounded writer.
    pub(super) fn write_grouped_headers(
        &self,
        writer: &mut BoundedLogWriter,
        values: BTreeMap<&str, Vec<&HeaderValue>>,
    ) {
        for (name_index, (name, header_values)) in
            values.into_iter().enumerate()
        {
            if name_index > 0 {
                let _ = writer.write_str("\n");
            }
            let _ = writer.write_str(name);
            let _ = writer.write_str(": [");
            self.write_header_values(writer, name, &header_values);
            if writer.is_full() {
                break;
            }
            let _ = writer.write_str("]");
        }
    }

    /// Redacts and writes every value for one header name.
    fn write_header_values(
        &self,
        writer: &mut BoundedLogWriter,
        name: &str,
        values: &[&HeaderValue],
    ) {
        for (value_index, value) in values.iter().enumerate() {
            if writer.is_full() {
                break;
            }
            if value_index > 0 {
                let _ = writer.write_str(", ");
            }
            let rendered = value.to_str().unwrap_or("<non-utf8>");
            let remaining = writer.remaining_bytes();
            if value.is_sensitive() {
                let redacted = self.header_field_redactor().mask_bounded(
                    Sensitivity::Secret,
                    rendered,
                    remaining,
                );
                let _ = writer.write_str(redacted.as_ref());
            } else {
                let redacted = self
                    .header_field_redactor()
                    .redact_bounded(name, rendered, remaining);
                let _ = writer.write_str(redacted.as_str());
            }
        }
    }
}
