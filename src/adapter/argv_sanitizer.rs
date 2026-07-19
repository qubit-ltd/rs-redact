// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::ffi::OsStr;

use crate::{
    FieldSanitizer,
    NameMatchMode,
    SensitivityLevel,
};

/// Sanitizes structured argv vectors for logs and diagnostics.
#[must_use = "the sanitizer must be used to produce sanitized argv"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgvSanitizer {
    /// Core sanitizer used for option and assignment values.
    field_sanitizer: FieldSanitizer,
}

impl ArgvSanitizer {
    /// Creates an argv sanitizer from a core field sanitizer.
    ///
    /// # Parameters
    ///
    /// * `field_sanitizer` - Core sanitizer used for option values.
    ///
    /// # Returns
    ///
    /// New argv sanitizer.
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

    /// Sanitizes one structured argv vector.
    ///
    /// This method handles `--token value`, `--token=value`, and
    /// `PASSWORD=value` forms. It does not parse shell syntax inside a single
    /// argument. A `--` delimiter stops separate-value option parsing, while
    /// self-contained `--token=value` and `PASSWORD=value` tokens remain
    /// eligible for sanitization because they require no positional inference.
    ///
    /// # Parameters
    ///
    /// * `argv` - Program and argument vector to render safely.
    /// * `match_mode` - Field-name matching mode for options and assignments.
    ///
    /// # Returns
    ///
    /// Sanitized argv tokens in input order.
    ///
    /// # Examples
    ///
    /// Sanitized argv must be used for diagnostics instead of being discarded.
    ///
    /// ```compile_fail
    /// #![deny(unused_must_use)]
    /// use qubit_sanitize::{ArgvSanitizer, NameMatchMode};
    ///
    /// let sanitizer = ArgvSanitizer::default();
    /// sanitizer.sanitize_argv(["cmd", "--token", "secret"], NameMatchMode::Exact);
    /// ```
    #[must_use = "use the returned sanitized argv instead of the original argv"]
    #[inline(always)]
    pub fn sanitize_argv<I, S>(
        &self,
        argv: I,
        match_mode: NameMatchMode,
    ) -> Vec<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.sanitize_argv_with_sensitivity(
            argv.into_iter().map(|arg| (arg, None)),
            match_mode,
        )
    }

    /// Sanitizes one argv vector with explicit per-token sensitivity.
    ///
    /// Explicit sensitivity controls only the rendered value. Parser state is
    /// still derived from the original token so option delimiters, pending
    /// option values, and inline assignments retain their normal semantics.
    ///
    /// # Parameters
    ///
    /// * `argv` - Program and argument tokens paired with optional explicit
    ///   sensitivity levels.
    /// * `match_mode` - Field-name matching mode for options and assignments.
    ///
    /// # Returns
    ///
    /// Sanitized argv tokens in input order.
    #[must_use = "use the returned sanitized argv instead of the original argv"]
    pub fn sanitize_argv_with_sensitivity<I, S>(
        &self,
        argv: I,
        match_mode: NameMatchMode,
    ) -> Vec<String>
    where
        I: IntoIterator<Item = (S, Option<SensitivityLevel>)>,
        S: AsRef<OsStr>,
    {
        let argv = argv.into_iter();
        let mut sanitized = Vec::with_capacity(argv.size_hint().0);
        let mut pending_sensitive_level = None;
        let mut parse_options = true;

        for (arg, explicit_level) in argv {
            let arg = arg.as_ref();
            let rendered = self.sanitize_arg(
                arg,
                match_mode,
                &mut pending_sensitive_level,
                &mut parse_options,
            );
            sanitized.push(match explicit_level {
                Some(level) => self
                    .field_sanitizer
                    .mask_value_at_level(arg.to_string_lossy().as_ref(), level)
                    .into_owned(),
                None => rendered,
            });
        }

        sanitized
    }

    /// Sanitizes one argv vector and formats it in argv-debug style.
    ///
    /// # Parameters
    ///
    /// * `argv` - Program and argument vector to render safely.
    /// * `match_mode` - Field-name matching mode for options and assignments.
    ///
    /// # Returns
    ///
    /// Debug-style sanitized argv string, for example
    /// `["cmd", "--token", "****"]`.
    #[must_use = "use the returned sanitized display instead of the original argv"]
    #[inline(always)]
    pub fn sanitize_argv_display<I, S>(
        &self,
        argv: I,
        match_mode: NameMatchMode,
    ) -> String
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        format!("{:?}", self.sanitize_argv(argv, match_mode))
    }

    /// Sanitizes one argv token while updating parser state.
    ///
    /// This method also updates pending-value sensitivity and whether option
    /// parsing remains enabled.
    ///
    /// # Parameters
    ///
    /// * `arg` - Argument token to sanitize.
    /// * `match_mode` - Field-name matching mode for options and assignments.
    /// * `pending_sensitive_level` - Sensitivity expected for the next value.
    /// * `parse_options` - Whether option tokens are still interpreted.
    ///
    /// # Returns
    ///
    /// The sanitized rendering of `arg`.
    #[must_use]
    fn sanitize_arg(
        &self,
        arg: &OsStr,
        match_mode: NameMatchMode,
        pending_sensitive_level: &mut Option<SensitivityLevel>,
        parse_options: &mut bool,
    ) -> String {
        let Some(arg) = arg.to_str() else {
            let encoded = arg.as_encoded_bytes();
            let may_take_separate_value = *parse_options
                && encoded.starts_with(b"-")
                && !encoded.contains(&b'=');
            let rendered = arg.to_string_lossy();
            *pending_sensitive_level =
                may_take_separate_value.then_some(SensitivityLevel::Secret);
            return self
                .field_sanitizer
                .mask_value_at_level(
                    rendered.as_ref(),
                    SensitivityLevel::Secret,
                )
                .into_owned();
        };
        let sensitive_option_level = (*parse_options)
            .then(|| self.sensitive_option_level(arg, match_mode))
            .flatten();
        if let Some(pending_level) = pending_sensitive_level.take() {
            if let Some(option_level) = sensitive_option_level {
                *pending_sensitive_level = Some(option_level);
                return self
                    .field_sanitizer
                    .mask_value_at_level(arg, pending_level)
                    .into_owned();
            } else {
                return self
                    .field_sanitizer
                    .mask_value_at_level(arg, pending_level)
                    .into_owned();
            }
        }
        if arg == "--" {
            *parse_options = false;
            return arg.to_string();
        }
        if let Some(value) = self.sanitize_assignment_arg(arg, match_mode) {
            return value;
        }
        if let Some(value) = self.sanitize_inline_option_arg(arg, match_mode) {
            return value;
        }
        if *parse_options && let Some(level) = sensitive_option_level {
            *pending_sensitive_level = Some(level);
        }
        arg.to_string()
    }

    /// Returns the sensitivity level represented by a bare option token.
    ///
    /// # Parameters
    ///
    /// * `arg` - Argument token that may name an option.
    /// * `match_mode` - Field-name matching mode for the option name.
    ///
    /// # Returns
    ///
    /// `Some(level)` when `arg` is a configured sensitive option, otherwise
    /// `None`.
    #[inline]
    fn sensitive_option_level(
        &self,
        arg: &str,
        match_mode: NameMatchMode,
    ) -> Option<SensitivityLevel> {
        let name = option_name(arg)?;
        self.field_sanitizer.sensitivity_for_name(name, match_mode)
    }

    /// Sanitizes one `KEY=value` argv token when the key is sensitive.
    ///
    /// # Parameters
    ///
    /// * `arg` - Argument token.
    /// * `match_mode` - Field-name matching mode for the assignment key.
    ///
    /// # Returns
    ///
    /// `Some(sanitized)` for assignment-like arguments, otherwise `None`.
    fn sanitize_assignment_arg(
        &self,
        arg: &str,
        match_mode: NameMatchMode,
    ) -> Option<String> {
        if arg.starts_with('-') {
            return None;
        }
        let (key, value) = arg.split_once('=')?;
        if key.is_empty() {
            return None;
        }
        let sanitized_value =
            self.field_sanitizer.sanitize_value(key, value, match_mode);
        if matches!(sanitized_value, std::borrow::Cow::Borrowed(_)) {
            return None;
        }
        Some(format!("{key}={sanitized_value}"))
    }

    /// Sanitizes one `--key=value` option token when the key is sensitive.
    ///
    /// # Parameters
    ///
    /// * `arg` - Argument token.
    /// * `match_mode` - Field-name matching mode for the option name.
    ///
    /// # Returns
    ///
    /// `Some(sanitized)` when `arg` is a sensitive inline option, otherwise
    /// `None`.
    #[inline]
    fn sanitize_inline_option_arg(
        &self,
        arg: &str,
        match_mode: NameMatchMode,
    ) -> Option<String> {
        if !arg.starts_with('-') || arg == "-" {
            return None;
        }
        let (left, value) = arg.split_once('=')?;
        let name = option_name(left)?;
        let level = self
            .field_sanitizer
            .sensitivity_for_name(name, match_mode)?;
        let sanitized_value =
            self.field_sanitizer.mask_value_at_level(value, level);
        Some(format!("{left}={sanitized_value}"))
    }
}

impl Default for ArgvSanitizer {
    /// Creates an argv sanitizer using [`FieldSanitizer::default`].
    ///
    /// # Returns
    ///
    /// Argv sanitizer configured with default sensitive fields and masks.
    #[inline(always)]
    fn default() -> Self {
        Self::new(FieldSanitizer::default())
    }
}

/// Returns an option name without leading dashes.
///
/// # Parameters
///
/// * `arg` - Argument token that may be an option.
///
/// # Returns
///
/// `Some(name)` for option-looking arguments, otherwise `None`.
#[inline]
fn option_name(arg: &str) -> Option<&str> {
    if !arg.starts_with('-') || arg == "-" {
        return None;
    }
    let name = arg.trim_start_matches('-');
    if name.is_empty() { None } else { Some(name) }
}
