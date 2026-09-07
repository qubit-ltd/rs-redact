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

use super::HttpPolicyExecutor;
use super::HttpRendered;
use crate::RedactionReason;
use crate::Sensitivity;
use crate::formats::http::internal::BoundedLogWriter;

/// Groups repeated header values under deterministically ordered names.
///
/// # Parameters
///
/// - `headers`: Header collection with potentially repeated names.
///
/// # Returns
///
/// Borrowed values grouped by sorted names while preserving each name’s value
/// order.
#[must_use]
pub(super) fn group_values(headers: &HeaderMap) -> BTreeMap<&str, Vec<&HeaderValue>> {
    let mut values = BTreeMap::<&str, Vec<&HeaderValue>>::new();
    for (name, value) in headers {
        values.entry(name.as_str()).or_default().push(value);
    }
    values
}

impl HttpPolicyExecutor<'_> {
    /// Redacts and deterministically renders all HTTP header values.
    ///
    /// # Parameters
    ///
    /// - `headers`: Admitted header collection including repeated values.
    /// - `max_output_bytes`: Final escaped output-byte ceiling.
    ///
    /// # Returns
    ///
    /// A bounded operation with deterministically ordered header names.
    #[must_use]
    pub(super) fn redact_headers_with_limit(&self, headers: &HeaderMap, max_output_bytes: usize) -> HttpRendered {
        let mut writer = BoundedLogWriter::new(max_output_bytes, false);
        let values = group_values(headers);
        self.write_grouped_headers(&mut writer, values);
        HttpRendered::new(writer.finish_operation(RedactionReason::OutputLimitReached))
    }

    /// Writes deterministically grouped headers to a bounded writer.
    ///
    /// # Parameters
    ///
    /// - `writer`: Destination retaining output closure and escaping state.
    /// - `values`: Header values grouped by lexicographically ordered names.
    pub(super) fn write_grouped_headers(
        &self,
        writer: &mut BoundedLogWriter,
        values: BTreeMap<&str, Vec<&HeaderValue>>,
    ) {
        for (name_index, (name, header_values)) in values.into_iter().enumerate() {
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
    ///
    /// # Parameters
    ///
    /// - `writer`: Destination stopped when output closes.
    /// - `name`: Header name used for policy classification.
    /// - `values`: Repeated values retained in their original order.
    fn write_header_values(&self, writer: &mut BoundedLogWriter, name: &str, values: &[&HeaderValue]) {
        for (value_index, value) in values.iter().enumerate() {
            if writer.is_full() {
                break;
            }
            if value_index > 0 {
                let _ = writer.write_str(", ");
            }
            let rendered = value.to_str().unwrap_or("<non-utf8>");
            let remaining = writer.remaining_bytes();
            if self.policy.is_disabled() {
                let _ = writer.write_str(rendered);
            } else {
                let sensitivity = if value.is_sensitive() {
                    Some(Sensitivity::Secret)
                } else {
                    self.header_field_redactor().sensitivity(name)
                };
                if let Some(level) = sensitivity {
                    let (redacted, truncated) = self
                        .policy
                        .masking()
                        .mask_bounded_with_truncation(level, rendered, remaining);
                    let _ = writer.write_str(redacted.as_ref());
                    if truncated {
                        writer.mark_truncated();
                    }
                } else {
                    let _ = writer.write_str(rendered);
                }
            }
        }
    }
}
