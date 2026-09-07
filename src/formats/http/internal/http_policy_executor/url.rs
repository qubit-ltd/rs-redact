// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! URL parsing, nested URL traversal, and query rendering.

use std::borrow::Cow;

use url::Url;

use super::HttpPolicyExecutor;
use super::HttpRendered;
use super::url_rules;
use crate::RedactionReason;
use crate::Sensitivity;
use crate::formats::http::UrlPathPolicy;
use crate::formats::http::internal::BoundedLogWriter;
use crate::formats::http::internal::form;
use crate::formats::http::internal::markers;
use crate::formats::http::internal::nested_url;
use crate::formats::http::internal::nested_url::NestedUrl;

impl HttpPolicyExecutor<'_> {
    /// Parses and redacts a URL, failing closed on invalid input.
    ///
    /// # Parameters
    ///
    /// - `input`: Admitted URL source text.
    /// - `output_limit`: Final escaped output-byte ceiling.
    ///
    /// # Returns
    ///
    /// A bounded redacted URL, or a marker retaining InvalidUri provenance.
    #[must_use]
    pub(super) fn redact_url_str(&self, input: &str, output_limit: usize) -> HttpRendered {
        if self.policy.is_disabled() {
            return self.finish_diagnostic_with_limit(input.to_owned(), output_limit, None);
        }
        Url::parse(input).map_or_else(
            |_| {
                self.finish_diagnostic_with_limit(
                    markers::INVALID_URL.to_string(),
                    output_limit,
                    Some(RedactionReason::InvalidUri),
                )
            },
            |url| {
                let (text, truncated) = self.redact_url_text_at_depth(&url, 0, output_limit);
                self.finish_rendered_url(text, truncated)
            },
        )
    }

    /// Produces a redacted URL under a bounded nested-URL recursion depth.
    ///
    /// # Parameters
    ///
    /// - `url`: Parsed URL to transform.
    /// - `depth`: Current nested-URL recursion depth.
    /// - `output_limit`: Final escaped output-byte ceiling.
    ///
    /// # Returns
    ///
    /// The escaped URL text and whether output was truncated.
    fn redact_url_text_at_depth(&self, url: &Url, depth: usize, output_limit: usize) -> (String, bool) {
        let mut writer = BoundedLogWriter::new(output_limit, false);
        let _ = writer.write_str(url.scheme());
        let _ = writer.write_str(":");
        if url.cannot_be_a_base() {
            let _ = writer.write_str(url.path());
            self.write_url_query(&mut writer, url, depth);
            self.write_url_fragment(&mut writer, url);
            return writer.finish();
        }
        let _ = writer.write_str("//");
        if !url.username().is_empty() {
            let masked = self
                .query_field_redactor()
                .mask_bounded(Sensitivity::High, url.username(), writer.remaining_bytes())
                .into_owned();
            let _ = writer.write_str(&masked);
        }
        if let Some(password) = url.password() {
            let _ = writer.write_str(":");
            let masked = self
                .query_field_redactor()
                .mask_bounded(Sensitivity::Secret, password, writer.remaining_bytes())
                .into_owned();
            let _ = writer.write_str(&masked);
        }
        if !url.username().is_empty() || url.password().is_some() {
            let _ = writer.write_str("@");
        }
        if let Some(host) = url.host_str() {
            let _ = writer.write_str(host);
        }
        if let Some(port) = url.port() {
            let _ = writer.write_str(":");
            let _ = writer.write_str(&port.to_string());
        }
        if self.policy.http().url_path_policy() == UrlPathPolicy::Redact && url.path() != "/" {
            let _ = writer.write_str("/<redacted>");
        } else {
            let _ = writer.write_str(url.path());
        }
        self.write_url_query(&mut writer, url, depth);
        self.write_url_fragment(&mut writer, url);
        writer.finish()
    }

    /// Writes a redacted query string without exceeding the URL output ceiling.
    ///
    /// # Parameters
    ///
    /// - `writer`: Bounded escaped destination for the URL.
    /// - `url`: Parsed URL whose optional query is visited.
    /// - `depth`: Current nested-URL recursion depth.
    fn write_url_query(&self, writer: &mut BoundedLogWriter, url: &Url, depth: usize) {
        let Some(query) = url.query() else {
            return;
        };
        let _ = writer.write_str("?");
        if !form::is_valid(query.as_bytes()) {
            let _ = writer.write_str(markers::INVALID_QUERY);
            return;
        }
        let query_limit = writer.remaining_bytes();
        let mut redacted_query = String::new();
        for (key, value) in url.query_pairs() {
            let remaining = query_limit.saturating_sub(redacted_query.len());
            let value = self
                .query_field_redactor()
                .redact_bounded(&key, &value, remaining)
                .into_inner();
            let (value, nested_truncated) = self.redact_nested_url_value(value, depth, remaining);
            if !form::append_pair_bounded(&mut redacted_query, &key, value.as_ref(), query_limit) {
                writer.mark_truncated();
                break;
            }
            if nested_truncated {
                writer.mark_truncated();
                break;
            }
        }
        let _ = writer.write_str(&redacted_query);
    }

    /// Writes a redacted URL fragment without exceeding the URL output ceiling.
    ///
    /// # Parameters
    ///
    /// - `writer`: Bounded escaped destination for the URL.
    /// - `url`: Parsed URL whose optional fragment is masked.
    fn write_url_fragment(&self, writer: &mut BoundedLogWriter, url: &Url) {
        let Some(fragment) = url.fragment() else {
            return;
        };
        let _ = writer.write_str("#");
        let (masked, truncated) =
            self.policy
                .masking()
                .mask_bounded_with_truncation(Sensitivity::High, fragment, writer.remaining_bytes());
        let _ = writer.write_str(masked.as_ref());
        if truncated {
            writer.mark_truncated();
        }
    }

    /// Redacts a complete HTTP URL embedded in a non-sensitive query value.
    ///
    /// # Type Parameters
    ///
    /// - `'value`: Borrow of an unchanged plain query value.
    ///
    /// # Parameters
    ///
    /// - `value`: Borrowed plain query value, or an owned value already
    ///   transformed by policy.
    /// - `depth`: Current nested-URL recursion depth.
    /// - `output_limit`: Remaining output-byte ceiling for the nested value.
    ///
    /// # Returns
    ///
    /// The original/transformed query value and whether nested output was
    /// truncated.
    fn redact_nested_url_value<'value>(
        &self,
        value: Cow<'value, str>,
        depth: usize,
        output_limit: usize,
    ) -> (Cow<'value, str>, bool) {
        let raw = match value {
            Cow::Borrowed(raw) => raw,
            Cow::Owned(masked) => return (Cow::Owned(masked), false),
        };
        match nested_url::detect(raw) {
            NestedUrl::NotUrl => (Cow::Borrowed(raw), false),
            NestedUrl::Parsed(url) if depth < url_rules::MAX_NESTED_URL_DEPTH => {
                let (text, truncated) = self.redact_url_text_at_depth(&url, depth + 1, output_limit);
                (Cow::Owned(text), truncated)
            }
            NestedUrl::Parsed(_) | NestedUrl::LimitExceeded => (Cow::Borrowed(markers::NESTED_URL_LIMIT), false),
            NestedUrl::Invalid => (Cow::Borrowed(markers::INVALID_URL), false),
        }
    }
}
