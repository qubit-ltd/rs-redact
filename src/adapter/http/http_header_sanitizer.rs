// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::collections::BTreeMap;

use http::{
    HeaderMap,
    HeaderName,
    HeaderValue,
};

use crate::{
    FieldSanitizer,
    NameMatchMode,
};

/// Sanitizes HTTP header values for logs and diagnostics.
#[must_use = "the sanitizer must be used to produce sanitized headers"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHeaderSanitizer {
    /// Core sanitizer used for HTTP header values.
    field_sanitizer: FieldSanitizer,
}

impl HttpHeaderSanitizer {
    /// Creates an HTTP header sanitizer from a core field sanitizer.
    ///
    /// # Parameters
    ///
    /// * `field_sanitizer` - Core sanitizer used for HTTP header values.
    ///
    /// # Returns
    ///
    /// New HTTP header sanitizer.
    #[inline(always)]
    pub const fn new(field_sanitizer: FieldSanitizer) -> Self {
        Self { field_sanitizer }
    }

    /// Returns the underlying core field sanitizer.
    ///
    /// # Returns
    ///
    /// Borrowed core field sanitizer.
    #[inline(always)]
    pub const fn field_sanitizer(&self) -> &FieldSanitizer {
        &self.field_sanitizer
    }

    /// Returns the underlying core field sanitizer mutably.
    ///
    /// # Returns
    ///
    /// Mutable core field sanitizer.
    #[inline(always)]
    pub fn field_sanitizer_mut(&mut self) -> &mut FieldSanitizer {
        &mut self.field_sanitizer
    }

    /// Sanitizes one HTTP header value by header name.
    ///
    /// Non-UTF-8 header values are rendered as `<non-utf8>` before applying
    /// sensitive-name masking.
    ///
    /// # Parameters
    ///
    /// * `name` - HTTP header name.
    /// * `value` - HTTP header value.
    /// * `match_mode` - Field-name matching mode for the header name.
    ///
    /// # Returns
    ///
    /// Sanitized header value for diagnostic output.
    #[must_use = "use the returned sanitized header value instead of the original value"]
    #[inline(always)]
    pub fn sanitize_value(
        &self,
        name: &HeaderName,
        value: &HeaderValue,
        match_mode: NameMatchMode,
    ) -> String {
        let value = value.to_str().unwrap_or("<non-utf8>");
        self.field_sanitizer
            .sanitize_value(name.as_str(), value, match_mode)
            .into_owned()
    }

    /// Sanitizes one HTTP header pair.
    ///
    /// # Parameters
    ///
    /// * `name` - HTTP header name.
    /// * `value` - HTTP header value.
    /// * `match_mode` - Field-name matching mode for the header name.
    ///
    /// # Returns
    ///
    /// Owned string pair preserving the header name and sanitizing the value
    /// when needed.
    #[must_use = "use the returned sanitized header pair instead of the original pair"]
    #[inline(always)]
    pub fn sanitize_pair(
        &self,
        name: &HeaderName,
        value: &HeaderValue,
        match_mode: NameMatchMode,
    ) -> (String, String) {
        (
            name.to_string(),
            self.sanitize_value(name, value, match_mode),
        )
    }

    /// Sanitizes an HTTP header map.
    ///
    /// Duplicate header values are grouped under the lowercase header name
    /// yielded by [`HeaderName::as_str`]. The returned map is sorted
    /// deterministically for debug output.
    ///
    /// # Parameters
    ///
    /// * `headers` - HTTP header map to render safely.
    /// * `match_mode` - Field-name matching mode for header names.
    ///
    /// # Returns
    ///
    /// Sanitized header names and values for diagnostic output.
    #[must_use = "use the returned sanitized headers instead of the original headers"]
    pub fn sanitize_headers(
        &self,
        headers: &HeaderMap,
        match_mode: NameMatchMode,
    ) -> BTreeMap<String, Vec<String>> {
        let mut result = BTreeMap::<String, Vec<String>>::new();
        for (name, value) in headers {
            result
                .entry(name.as_str().to_string())
                .or_default()
                .push(self.sanitize_value(name, value, match_mode));
        }
        result
    }
}

impl Default for HttpHeaderSanitizer {
    /// Creates an HTTP header sanitizer using [`FieldSanitizer::default`].
    #[inline(always)]
    fn default() -> Self {
        Self::new(FieldSanitizer::default())
    }
}
