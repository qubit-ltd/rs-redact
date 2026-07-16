// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use ::url::{
    ParseError,
    Url,
    form_urlencoded,
};

use crate::{
    FieldSanitizer,
    NameMatchMode,
    SensitivityLevel,
};

/// Sanitizes URLs for logs and diagnostics.
#[must_use = "the sanitizer must be used to produce sanitized URLs"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlSanitizer {
    /// Core sanitizer used for query parameter values and masks.
    field_sanitizer: FieldSanitizer,
}

impl UrlSanitizer {
    /// Creates a URL sanitizer from a core field sanitizer.
    ///
    /// # Parameters
    ///
    /// * `field_sanitizer` - Core sanitizer used for query parameters and
    ///   masks.
    ///
    /// # Returns
    ///
    /// New URL sanitizer.
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

    /// Returns a sanitized URL string.
    ///
    /// Userinfo and fragment values are masked with the configured
    /// high-sensitivity mask. Passwords use the secret-sensitivity mask. Query
    /// parameter values are sanitized by parameter name, preserving parameter
    /// order and duplicates. URL paths are kept unchanged because path-segment
    /// semantics are application-specific.
    ///
    /// # Parameters
    ///
    /// * `url` - Parsed URL to sanitize.
    /// * `match_mode` - Field-name matching mode for query parameters.
    ///
    /// # Returns
    ///
    /// Sanitized URL string for diagnostic output.
    #[must_use = "use the returned sanitized URL instead of the original URL"]
    pub fn sanitize_url(&self, url: &Url, match_mode: NameMatchMode) -> String {
        let mut sanitized = url.clone();
        if !sanitized.username().is_empty() {
            let username = mask_url_component(
                &self.field_sanitizer,
                sanitized.username(),
                SensitivityLevel::High,
            );
            let _ = sanitized.set_username(&username);
        }
        if let Some(password) = sanitized.password() {
            let password = mask_url_component(
                &self.field_sanitizer,
                password,
                SensitivityLevel::Secret,
            );
            let _ = sanitized.set_password(Some(&password));
        }
        if let Some(fragment) = sanitized.fragment() {
            let fragment = mask_url_component(
                &self.field_sanitizer,
                fragment,
                SensitivityLevel::High,
            );
            sanitized.set_fragment(Some(&fragment));
        }
        let Some(_) = sanitized.query() else {
            return sanitized.to_string();
        };

        let mut serializer = form_urlencoded::Serializer::new(String::new());
        for (key, value) in url.query_pairs() {
            let sanitized_value = self.field_sanitizer.sanitize_value(
                key.as_ref(),
                value.as_ref(),
                match_mode,
            );
            serializer.append_pair(key.as_ref(), sanitized_value.as_ref());
        }
        sanitized.set_query(Some(&serializer.finish()));
        sanitized.to_string()
    }

    /// Parses and sanitizes one URL string.
    ///
    /// # Parameters
    ///
    /// * `url` - Absolute URL string to parse and sanitize.
    /// * `match_mode` - Field-name matching mode for query parameters.
    ///
    /// # Returns
    ///
    /// Sanitized URL string.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when `url` is not parseable by [`Url::parse`].
    #[inline(always)]
    pub fn sanitize_url_str(
        &self,
        url: &str,
        match_mode: NameMatchMode,
    ) -> Result<String, ParseError> {
        Url::parse(url).map(|url| self.sanitize_url(&url, match_mode))
    }
}

impl Default for UrlSanitizer {
    /// Creates a URL sanitizer using [`FieldSanitizer::default`].
    #[inline(always)]
    fn default() -> Self {
        Self::new(FieldSanitizer::default())
    }
}

/// Masks one structural URL component.
///
/// # Parameters
///
/// * `sanitizer` - Core sanitizer containing mask policies.
/// * `value` - Component value to mask.
/// * `level` - Sensitivity level that selects the mask policy.
///
/// # Returns
///
/// Masked component value.
#[must_use = "use the returned masked component instead of the original component"]
#[inline(always)]
fn mask_url_component(
    sanitizer: &FieldSanitizer,
    value: &str,
    level: SensitivityLevel,
) -> String {
    sanitizer
        .policy()
        .mask_policies()
        .for_level(level)
        .mask(value)
        .into_owned()
}
