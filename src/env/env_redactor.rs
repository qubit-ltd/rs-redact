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
    DiagnosticInputBudget, LogOutputLimit, LogSafeText, RedactedText, Redactor, Sensitivity,
    policy::ResolvedField, text::internal::BoundedLogEscapeWriter,
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
        let value = self.redactor.redact_field(name, value).into_owned();
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
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime of environment names and values yielded by the
    ///   iterator.
    /// * `I` - Iterator source yielding borrowed environment pairs.
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
        let mut input_budget = self.redactor.policy().diagnostic_budget().input_budget();
        self.redact_os_pairs_with_input_budget(pairs, &mut input_budget)
    }

    /// Redacts environment pairs using shared source-byte accounting.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime of environment names and values yielded by the
    ///   iterator.
    /// * `I` - Iterator source yielding borrowed environment pairs.
    ///
    /// # Parameters
    ///
    /// * `pairs` - Operating-system environment names and values to redact.
    /// * `input_budget` - Shared source-byte accounting for this diagnostic.
    ///
    /// # Returns
    ///
    /// A debug-style log-safe list, ending with `<truncated>` when the next
    /// pair cannot be inspected within the shared budget.
    pub fn redact_os_pairs_with_input_budget<'a, I>(
        &self,
        pairs: I,
        input_budget: &mut DiagnosticInputBudget,
    ) -> LogSafeText<'static>
    where
        I: IntoIterator<Item = (&'a OsStr, &'a OsStr)>,
    {
        let budget = self.redactor.policy().diagnostic_budget();
        let limit = LogOutputLimit::from(budget);
        let mut writer = BoundedLogEscapeWriter::new(limit);
        let _ = writer.write_str("[");
        let mut has_item = false;

        for (name, value) in pairs {
            if writer.is_truncated() {
                break;
            }
            let pair_bytes = name
                .as_encoded_bytes()
                .len()
                .saturating_add(value.as_encoded_bytes().len());
            if !input_budget.reserve(pair_bytes) {
                write_debug_item(&mut writer, &mut has_item, "<truncated>");
                break;
            }
            let pair = self.redact_os_pair_bounded(name, value, budget.max_output_bytes());
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

    /// Renders one environment pair while bounding any materialized mask.
    ///
    /// # Parameters
    ///
    /// * `name` - Environment-variable name used for classification.
    /// * `value` - Environment-variable value to redact when sensitive.
    /// * `max_mask_bytes` - Maximum bytes materialized for one mask.
    ///
    /// # Returns
    ///
    /// A log-safe assignment whose mask allocation fits `max_mask_bytes`.
    fn redact_os_pair_bounded(&self, name: &OsStr, value: &OsStr, max_mask_bytes: usize) -> String {
        let pair = match (name.to_str(), value.to_str()) {
            (Some(name), Some(value)) => {
                let resolved = self.redactor.policy().resolve_field(name);
                let value = match resolved {
                    ResolvedField::Sensitive { sensitivity } => self
                        .redactor
                        .policy()
                        .masking()
                        .mask_bounded(sensitivity, value, max_mask_bytes)
                        .into_owned(),
                    ResolvedField::PassThrough => value.to_owned(),
                };
                RedactedEnvPair::new(log_safe_owned(name.to_owned()), log_safe_owned(value))
            }
            _ => RedactedEnvPair::new(
                log_safe_owned(name.to_string_lossy().into_owned()),
                log_safe_owned(
                    self.redactor
                        .policy()
                        .masking()
                        .mask_opaque_bounded(Sensitivity::Secret, max_mask_bytes),
                ),
            ),
        };
        pair.to_string()
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
