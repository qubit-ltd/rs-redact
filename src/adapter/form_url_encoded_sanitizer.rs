// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use ::url::form_urlencoded;

use crate::{
    FieldSanitizer,
    NameMatchMode,
};

/// Sanitizes `application/x-www-form-urlencoded` payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormUrlEncodedSanitizer {
    /// Core sanitizer used for form field values.
    field_sanitizer: FieldSanitizer,
}

impl FormUrlEncodedSanitizer {
    /// Creates a form sanitizer from a core field sanitizer.
    ///
    /// # Parameters
    ///
    /// * `field_sanitizer` - Core sanitizer used for form field values.
    ///
    /// # Returns
    ///
    /// New form sanitizer.
    pub const fn new(field_sanitizer: FieldSanitizer) -> Self {
        Self { field_sanitizer }
    }

    /// Returns the underlying core field sanitizer.
    ///
    /// # Returns
    ///
    /// Borrowed core field sanitizer.
    pub const fn field_sanitizer(&self) -> &FieldSanitizer {
        &self.field_sanitizer
    }

    /// Returns the underlying core field sanitizer mutably.
    ///
    /// # Returns
    ///
    /// Mutable core field sanitizer.
    pub fn field_sanitizer_mut(&mut self) -> &mut FieldSanitizer {
        &mut self.field_sanitizer
    }

    /// Sanitizes URL-encoded form bytes.
    ///
    /// Field order and duplicate keys are preserved. The returned string is
    /// serialized as valid URL-encoded form data.
    ///
    /// # Parameters
    ///
    /// * `form` - URL-encoded form bytes.
    /// * `match_mode` - Field-name matching mode for form keys.
    ///
    /// # Returns
    ///
    /// Sanitized URL-encoded form string.
    pub fn sanitize_bytes(
        &self,
        form: &[u8],
        match_mode: NameMatchMode,
    ) -> String {
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        for (key, value) in form_urlencoded::parse(form) {
            let sanitized_value = self.field_sanitizer.sanitize_value(
                key.as_ref(),
                value.as_ref(),
                match_mode,
            );
            serializer.append_pair(key.as_ref(), sanitized_value.as_ref());
        }
        serializer.finish()
    }

    /// Sanitizes a URL-encoded form string.
    ///
    /// # Parameters
    ///
    /// * `form` - URL-encoded form string.
    /// * `match_mode` - Field-name matching mode for form keys.
    ///
    /// # Returns
    ///
    /// Sanitized URL-encoded form string.
    pub fn sanitize_str(
        &self,
        form: &str,
        match_mode: NameMatchMode,
    ) -> String {
        self.sanitize_bytes(form.as_bytes(), match_mode)
    }
}

impl Default for FormUrlEncodedSanitizer {
    /// Creates a form sanitizer using [`FieldSanitizer::default`].
    fn default() -> Self {
        Self::new(FieldSanitizer::default())
    }
}
