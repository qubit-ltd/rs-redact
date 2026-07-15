// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
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
};

/// Sanitizes environment variable values.
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
    /// Non-UTF-8 keys and values are rendered lossily for diagnostics.
    ///
    /// # Parameters
    ///
    /// * `key` - Environment variable key.
    /// * `value` - Environment variable value.
    /// * `match_mode` - Field-name matching mode for the key.
    ///
    /// # Returns
    ///
    /// Owned string pair suitable for logs and errors.
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
        let key = key.as_ref().to_string_lossy();
        let value = value.as_ref().to_string_lossy();
        (
            key.to_string(),
            self.sanitize_value(key.as_ref(), value.as_ref(), match_mode)
                .into_owned(),
        )
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
}

impl Default for EnvSanitizer {
    /// Creates an environment sanitizer using [`FieldSanitizer::default`].
    fn default() -> Self {
        Self::new(FieldSanitizer::default())
    }
}
