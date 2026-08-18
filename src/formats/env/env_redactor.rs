// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Environment-variable pair and assignment redaction.

use std::borrow::Cow;
use std::ffi::OsStr;

use super::RedactedEnv;
use super::RedactedEnvPair;
use crate::RedactedText;
use crate::Redactor;
use crate::Sensitivity;
use crate::output::MaskedValue;
use crate::policy::ResolvedField;

/// Applies one immutable redaction policy to environment-variable values.
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
    #[must_use]
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
    #[must_use]
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
    #[must_use]
    pub fn redact_pair(&self, name: &str, value: &str) -> RedactedEnvPair {
        self.redact_os_pair(OsStr::new(name), OsStr::new(value))
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
    #[must_use]
    pub fn redact_os_pair(&self, name: &OsStr, value: &OsStr) -> RedactedEnvPair {
        let max_output = usize::MAX;
        let (rendered, locally_truncated) = self.redact_os_pair_bounded(name, value, max_output);
        if locally_truncated {
            RedactedEnvPair::truncated(RedactedText::from_escaped(rendered))
        } else {
            RedactedEnvPair::complete(RedactedText::from_escaped(rendered))
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
    /// A bounded batch result whose completion state distinguishes full
    /// rendering, a non-empty safe truncation marker, and empty exhaustion.
    /// Input is pulled lazily and is not advanced after exhaustion.
    #[must_use]
    pub fn redact_os_pairs<'a, I>(&self, pairs: I) -> RedactedEnv
    where
        I: IntoIterator<Item = (&'a OsStr, &'a OsStr)>,
        I::IntoIter: ExactSizeIterator,
    {
        let mut writer = String::from("[");
        let mut has_item = false;
        let mut locally_truncated = false;
        for (name, value) in pairs {
            let (pair, truncated) = self.redact_os_pair_bounded(name, value, usize::MAX);
            locally_truncated |= truncated;
            write_debug_item(&mut writer, &mut has_item, &pair);
        }
        writer.push(']');
        let rendered = writer;
        if locally_truncated {
            RedactedEnv::truncated(RedactedText::from_escaped(rendered))
        } else {
            RedactedEnv::complete(RedactedText::from_escaped(rendered))
        }
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
    #[must_use]
    pub fn redact_assignment(&self, assignment: &str) -> RedactedEnvPair {
        let (name, value) = assignment.split_once('=').unwrap_or((assignment, ""));
        self.redact_pair(name, value)
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
    /// A log-safe assignment whose mask allocation fits `max_mask_bytes`, and
    /// whether the configured mask was locally shortened.
    pub(super) fn redact_os_pair_bounded(&self, name: &OsStr, value: &OsStr, max_mask_bytes: usize) -> (String, bool) {
        let (pair, locally_truncated) = match (name.to_str(), value.to_str()) {
            (Some(name), Some(value)) => {
                let resolved = self.redactor.policy().resolve_field(name);
                let (value, locally_truncated) = match resolved {
                    ResolvedField::Sensitive { sensitivity } => {
                        let (masked, truncated) = self.redactor.policy().masking().mask_bounded_with_truncation(
                            sensitivity,
                            value,
                            max_mask_bytes,
                        );
                        (masked.into_owned(), truncated)
                    }
                    ResolvedField::PassThrough => (value.to_owned(), false),
                };
                (
                    RedactedEnvPair::new(log_safe_owned(name.to_owned()), log_safe_owned(value)),
                    locally_truncated,
                )
            }
            _ => {
                let masking = self.redactor.policy().masking();
                let complete_len = masking.mask_opaque(Sensitivity::Secret).len();
                let masked = masking.mask_opaque_bounded(Sensitivity::Secret, max_mask_bytes);
                let locally_truncated = masked.len() < complete_len;
                (
                    RedactedEnvPair::new(
                        log_safe_owned(name.to_string_lossy().into_owned()),
                        log_safe_owned(masked),
                    ),
                    locally_truncated,
                )
            }
        };
        (pair.to_string(), locally_truncated)
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
#[must_use]
fn log_safe_owned(value: String) -> RedactedText {
    MaskedValue::new(Cow::Owned(value)).escape_for_log()
}

/// Appends one redacted assignment to a bounded debug-style list.
///
/// # Parameters
///
/// * `writer` - Escaped bounded output destination.
/// * `has_item` - Whether a preceding list item has already been rendered.
/// * `item` - Redacted assignment safe to format.
pub(super) fn write_debug_item(writer: &mut String, has_item: &mut bool, item: &str) {
    if *has_item {
        writer.push_str(", ");
    }
    writer.push_str(&format!("{item:?}"));
    *has_item = true;
}
