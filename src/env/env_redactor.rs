// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Environment-variable pair and assignment redaction.

use std::{borrow::Cow, ffi::OsStr, fmt::Write as _};

use crate::{
    LogOutputLimit, LogSafeText, RedactedText, Redactor, Sensitivity,
    text::internal::BoundedLogEscapeWriter,
};

use super::RedactedEnvPair;

/// Applies one immutable redaction policy to environment-variable values.
#[must_use = "use the redactor to produce safe environment diagnostics"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvRedactor {
    /// Core redactor supplying field classification and masking policies.
    redactor: Redactor,
}

impl EnvRedactor {
    /// Creates an environment redactor from a core redactor.
    ///
    /// # Parameters
    ///
    /// * `redactor` - Core redactor whose immutable policy will be used.
    ///
    /// # Returns
    ///
    /// An environment redactor owning the supplied policy snapshot.
    #[inline(always)]
    pub const fn new(redactor: Redactor) -> Self {
        Self { redactor }
    }

    /// Returns the core redactor backing this adapter.
    ///
    /// # Returns
    ///
    /// A borrowed view of the core redactor.
    #[inline(always)]
    pub const fn redactor(&self) -> &Redactor {
        &self.redactor
    }

    /// Redacts one UTF-8 environment-variable pair.
    ///
    /// Both components are escaped before they can be displayed. The value is
    /// classified from `name` using the adapter's immutable policy.
    ///
    /// # Parameters
    ///
    /// * `name` - Environment-variable name used for classification.
    /// * `value` - Environment-variable value to redact when sensitive.
    ///
    /// # Returns
    ///
    /// A log-safe pair rendered as `NAME=VALUE`.
    #[inline]
    pub fn redact_pair(&self, name: &str, value: &str) -> RedactedEnvPair {
        let value = self.redactor.redact(name, value).into_owned();
        let name = log_safe_owned(name.to_owned());
        RedactedEnvPair::new(name, log_safe_owned(value))
    }

    /// Redacts one environment pair whose components may not be UTF-8.
    ///
    /// If either component is invalid UTF-8, the original value is never
    /// rendered or supplied to an edge-preserving mask. Instead, the secret
    /// opaque replacement is used. A non-UTF-8 name is
    /// rendered lossily and escaped for diagnostics.
    ///
    /// # Parameters
    ///
    /// * `name` - Operating-system environment-variable name.
    /// * `value` - Operating-system environment-variable value.
    ///
    /// # Returns
    ///
    /// A fail-closed, log-safe pair rendered as `NAME=VALUE`.
    pub fn redact_os_pair(&self, name: &OsStr, value: &OsStr) -> RedactedEnvPair {
        match (name.to_str(), value.to_str()) {
            (Some(name), Some(value)) => self.redact_pair(name, value),
            _ => {
                let name = log_safe_owned(name.to_string_lossy().into_owned());
                let value = self.mask_opaque_value();
                RedactedEnvPair::new(name, log_safe_owned(value))
            }
        }
    }

    /// Redacts environment pairs into one bounded log-safe list.
    ///
    /// The adapter stops before inspecting a pair that would exceed the
    /// policy's diagnostic input budget. It also stops once the escaped list
    /// reaches the diagnostic output budget.
    ///
    /// # Parameters
    ///
    /// * `pairs` - Operating-system environment names and values to redact.
    ///
    /// # Returns
    ///
    /// A debug-style log-safe list of redacted assignments.
    pub fn redact_os_pairs<'a, I>(&self, pairs: I) -> LogSafeText<'static>
    where
        I: IntoIterator<Item = (&'a OsStr, &'a OsStr)>,
    {
        let budget = self.redactor.policy().diagnostic_budget();
        let limit = LogOutputLimit::new(budget.max_output_bytes())
            .expect("diagnostic budgets always satisfy the log output minimum");
        let mut writer = BoundedLogEscapeWriter::new(limit);
        let _ = writer.write_str("[");
        let mut remaining_input_bytes = budget.max_input_bytes();
        let mut has_item = false;

        for (name, value) in pairs {
            if writer.is_truncated() {
                break;
            }
            let pair_bytes = name
                .as_encoded_bytes()
                .len()
                .saturating_add(value.as_encoded_bytes().len());
            if pair_bytes > remaining_input_bytes {
                write_debug_item(&mut writer, &mut has_item, "<truncated>");
                break;
            }
            remaining_input_bytes -= pair_bytes;
            let pair = self.redact_os_pair(name, value).to_string();
            write_debug_item(&mut writer, &mut has_item, &pair);
        }
        if !writer.is_truncated() {
            let _ = writer.write_str("]");
        }
        LogSafeText::from_escaped(Cow::Owned(writer.finish()))
    }

    /// Redacts one UTF-8 `NAME=value` assignment.
    ///
    /// Input without `=` is treated as a name with an empty value and therefore
    /// renders as `NAME=`.
    ///
    /// # Parameters
    ///
    /// * `assignment` - Assignment text to split at its first equals sign.
    ///
    /// # Returns
    ///
    /// A log-safe pair rendered as `NAME=VALUE`.
    #[inline]
    pub fn redact_assignment(&self, assignment: &str) -> RedactedEnvPair {
        let (name, value) = assignment.split_once('=').unwrap_or((assignment, ""));
        self.redact_pair(name, value)
    }

    /// Produces the configured secret replacement without reading opaque bytes.
    ///
    /// # Returns
    ///
    /// The secret-level opaque replacement.
    #[inline(always)]
    fn mask_opaque_value(&self) -> String {
        self.redactor
            .policy()
            .masking()
            .mask_opaque(Sensitivity::Secret)
            .to_owned()
    }
}

impl Default for EnvRedactor {
    /// Creates an environment redactor from the current default policy
    /// snapshot.
    ///
    /// # Returns
    ///
    /// An environment redactor backed by [`Redactor::default`].
    fn default() -> Self {
        Self::new(Redactor::default())
    }
}

/// Escapes an owned string and labels it safe for text-log display.
///
/// # Parameters
///
/// * `value` - Owned text to escape.
///
/// # Returns
///
/// An owned typed log-safe value.
#[inline(always)]
fn log_safe_owned(value: String) -> LogSafeText<'static> {
    RedactedText::new(Cow::Owned(value)).escape_for_log()
}

/// Appends one redacted assignment to a bounded debug-style list.
///
/// # Parameters
///
/// * `writer` - Escaped bounded output destination.
/// * `has_item` - Whether a preceding list item has already been rendered.
/// * `item` - Redacted assignment safe to format.
fn write_debug_item(writer: &mut BoundedLogEscapeWriter, has_item: &mut bool, item: &str) {
    if *has_item {
        let _ = writer.write_str(", ");
    }
    let _ = write!(writer, "{item:?}");
    *has_item = true;
}
