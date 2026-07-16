// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::ffi::OsStr;

use crate::{
    FieldSanitizer,
    NameMatchMode,
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
    /// argument.
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
    pub fn sanitize_argv<I, S>(
        &self,
        argv: I,
        match_mode: NameMatchMode,
    ) -> Vec<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut sanitized = Vec::new();
        let mut pending_sensitive_name: Option<String> = None;
        let mut parse_options = true;

        for arg in argv {
            let arg = arg.as_ref().to_string_lossy().into_owned();
            let sensitive_option_name = parse_options
                .then(|| self.sensitive_option_name(&arg, match_mode))
                .flatten();
            if let Some(name) = pending_sensitive_name.take() {
                if let Some(name) = sensitive_option_name {
                    pending_sensitive_name = Some(name.to_string());
                    sanitized.push(arg);
                } else {
                    sanitized.push(
                        self.sanitize_sensitive_value(&name, &arg, match_mode),
                    );
                }
                continue;
            }

            if arg == "--" {
                parse_options = false;
                sanitized.push(arg);
                continue;
            }

            if let Some(value) = self.sanitize_assignment_arg(&arg, match_mode)
            {
                sanitized.push(value);
                continue;
            }

            if parse_options {
                if let Some(value) =
                    self.sanitize_inline_option_arg(&arg, match_mode)
                {
                    sanitized.push(value);
                    continue;
                }
                if let Some(name) = sensitive_option_name {
                    pending_sensitive_name = Some(name.to_string());
                }
            }

            sanitized.push(arg);
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

    /// Returns the sensitive field name represented by a bare option token.
    ///
    /// # Parameters
    ///
    /// * `arg` - Argument token that may name an option.
    /// * `match_mode` - Field-name matching mode for the option name.
    ///
    /// # Returns
    ///
    /// `Some(name)` when `arg` is a configured sensitive option, otherwise
    /// `None`.
    fn sensitive_option_name<'a>(
        &self,
        arg: &'a str,
        match_mode: NameMatchMode,
    ) -> Option<&'a str> {
        option_name(arg).filter(|name| {
            self.field_sanitizer
                .sensitivity_for_name(name, match_mode)
                .is_some()
        })
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

    /// Sanitizes one value whose option or assignment name is already
    /// sensitive.
    ///
    /// # Parameters
    ///
    /// * `name` - Sensitive option or assignment name.
    /// * `value` - Value to sanitize.
    /// * `match_mode` - Field-name matching mode for `name`.
    ///
    /// # Returns
    ///
    /// Sanitized value according to the sensitivity level resolved from `name`.
    #[must_use = "use the returned sanitized value instead of the original value"]
    #[inline(always)]
    fn sanitize_sensitive_value(
        &self,
        name: &str,
        value: &str,
        match_mode: NameMatchMode,
    ) -> String {
        self.field_sanitizer
            .sanitize_value(name, value, match_mode)
            .into_owned()
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
        self.field_sanitizer
            .sensitivity_for_name(name, match_mode)?;
        let sanitized_value =
            self.sanitize_sensitive_value(name, value, match_mode);
        Some(format!("{left}={sanitized_value}"))
    }
}

impl Default for ArgvSanitizer {
    /// Creates an argv sanitizer using [`FieldSanitizer::default`].
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
fn option_name(arg: &str) -> Option<&str> {
    if !arg.starts_with('-') || arg == "-" {
        return None;
    }
    let name = arg.trim_start_matches('-');
    if name.is_empty() { None } else { Some(name) }
}
