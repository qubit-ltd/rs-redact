// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::{
    borrow::Cow,
    ffi::OsStr,
};

use crate::{
    FieldSanitizer,
    NameMatchMode,
    SensitivityLevel,
};

/// Sanitizes environment variable values.
#[must_use = "the sanitizer must be used to produce sanitized environment values"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvSanitizer {
    /// Core sanitizer used for environment variable values.
    field_sanitizer: FieldSanitizer,
}

impl EnvSanitizer {
    /// Creates an environment sanitizer from a core field sanitizer.
    ///
    /// # Parameters
    ///
    /// * `field_sanitizer` - Core sanitizer used for variable values.
    ///
    /// # Returns
    ///
    /// New environment sanitizer.
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

    /// Sanitizes one environment variable value by key.
    ///
    /// # Parameters
    ///
    /// * `key` - Environment variable key.
    /// * `value` - Environment variable value.
    /// * `match_mode` - Field-name matching mode for the key.
    ///
    /// # Returns
    ///
    /// Borrowed `value` when `key` is not sensitive, otherwise an owned masked
    /// value.
    #[must_use = "use the returned sanitized value instead of the original value"]
    #[inline(always)]
    pub fn sanitize_value<'a>(
        &self,
        key: &str,
        value: &'a str,
        match_mode: NameMatchMode,
    ) -> Cow<'a, str> {
        self.field_sanitizer.sanitize_value(key, value, match_mode)
    }

    /// Sanitizes one environment variable pair.
    ///
    /// # Parameters
    ///
    /// * `key` - Environment variable key.
    /// * `value` - Environment variable value.
    /// * `match_mode` - Field-name matching mode for the key.
    ///
    /// # Returns
    ///
    /// Owned pair preserving the key and sanitizing the value when needed.
    #[must_use = "use the returned sanitized pair instead of the original pair"]
    #[inline(always)]
    pub fn sanitize_pair(
        &self,
        key: &str,
        value: &str,
        match_mode: NameMatchMode,
    ) -> (String, String) {
        (
            key.to_string(),
            self.sanitize_value(key, value, match_mode).into_owned(),
        )
    }

    /// Sanitizes one environment variable pair that may not be UTF-8.
    ///
    /// Non-UTF-8 keys are rendered lossily. If either component is not UTF-8,
    /// the complete value is redacted because the key cannot be classified
    /// reliably or the value cannot be rendered faithfully.
    ///
    /// # Parameters
    ///
    /// * `key` - Environment variable key.
    /// * `value` - Environment variable value.
    /// * `match_mode` - Field-name matching mode for the key.
    ///
    /// # Returns
    ///
    /// Owned string pair with a sanitized value. The strings are not escaped;
    /// render them with `Debug` formatting before writing untrusted control
    /// characters to a single-line log.
    #[must_use = "use the returned sanitized pair instead of the original pair"]
    #[inline]
    pub fn sanitize_os_pair<K, V>(
        &self,
        key: K,
        value: V,
        match_mode: NameMatchMode,
    ) -> (String, String)
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.sanitize_os_pair_ref(key.as_ref(), value.as_ref(), match_mode)
    }

    /// Sanitizes one `KEY=value` assignment.
    ///
    /// Strings without `=` are returned unchanged.
    ///
    /// # Parameters
    ///
    /// * `assignment` - Environment assignment text.
    /// * `match_mode` - Field-name matching mode for the assignment key.
    ///
    /// # Returns
    ///
    /// Sanitized assignment text.
    #[must_use = "use the returned sanitized assignment instead of the original assignment"]
    #[inline]
    pub fn sanitize_assignment(
        &self,
        assignment: &str,
        match_mode: NameMatchMode,
    ) -> String {
        let Some((key, value)) = assignment.split_once('=') else {
            return assignment.to_string();
        };
        let sanitized_value = self.sanitize_value(key, value, match_mode);
        format!("{key}={sanitized_value}")
    }

    /// Sanitizes many `KEY=value` assignments.
    ///
    /// # Parameters
    ///
    /// * `assignments` - Assignment strings to sanitize.
    /// * `match_mode` - Field-name matching mode for assignment keys.
    ///
    /// # Returns
    ///
    /// Sanitized assignment strings in input order.
    #[must_use = "use the returned sanitized assignments instead of the originals"]
    pub fn sanitize_assignments<I, S>(
        &self,
        assignments: I,
        match_mode: NameMatchMode,
    ) -> Vec<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        assignments
            .into_iter()
            .map(|assignment| {
                self.sanitize_assignment(assignment.as_ref(), match_mode)
            })
            .collect()
    }

    /// Sanitizes assignments and formats them in escaped debug style.
    ///
    /// # Parameters
    ///
    /// * `assignments` - Assignment strings to sanitize and render.
    /// * `match_mode` - Field-name matching mode for assignment keys.
    ///
    /// # Returns
    ///
    /// Debug-style sanitized assignment list with control characters escaped,
    /// for example `["PASSWORD=<redacted>", "MODE=debug\\nnext"]`.
    #[must_use = "use the returned sanitized display instead of the original assignments"]
    #[inline(always)]
    pub fn sanitize_assignments_display<I, S>(
        &self,
        assignments: I,
        match_mode: NameMatchMode,
    ) -> String
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        format!("{:?}", self.sanitize_assignments(assignments, match_mode))
    }

    /// Sanitizes one borrowed environment pair that may not be UTF-8.
    ///
    /// # Parameters
    ///
    /// * `key` - Borrowed environment variable key.
    /// * `value` - Borrowed environment variable value.
    /// * `match_mode` - Field-name matching mode for the key.
    ///
    /// # Returns
    ///
    /// Owned string pair preserving the rendered key and sanitizing the value.
    fn sanitize_os_pair_ref(
        &self,
        key: &OsStr,
        value: &OsStr,
        match_mode: NameMatchMode,
    ) -> (String, String) {
        let rendered_key = key.to_string_lossy();
        let rendered_value = value.to_string_lossy();
        let sanitized_value = match (key.to_str(), value.to_str()) {
            (Some(key), Some(value)) => {
                self.sanitize_value(key, value, match_mode).into_owned()
            }
            _ => self
                .field_sanitizer
                .mask_value_at_level(
                    rendered_value.as_ref(),
                    SensitivityLevel::Secret,
                )
                .into_owned(),
        };
        (rendered_key.into_owned(), sanitized_value)
    }
}

impl Default for EnvSanitizer {
    /// Creates an environment sanitizer using [`FieldSanitizer::default`].
    #[inline(always)]
    fn default() -> Self {
        Self::new(FieldSanitizer::default())
    }
}
