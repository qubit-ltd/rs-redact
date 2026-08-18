// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Explicit and heuristic argument-vector redaction.

use std::ffi::OsStr;

use super::ArgvItem;
use super::RedactedArgv;
use super::pending_field::PendingField;
use crate::Redactor;
use crate::Sensitivity;
use crate::policy::ResolvedField;

/// Applies one immutable redaction policy to argument vectors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgvRedactor {
    /// Core redactor supplying field classification and masking policies.
    redactor: Redactor,
}

impl ArgvRedactor {
    /// Creates an argv redactor from a core redactor.
    ///
    /// # Parameters
    ///
    /// * `redactor` - Core redactor whose immutable policy will be used.
    ///
    /// # Returns
    ///
    /// An argv redactor owning the supplied policy snapshot.
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

    /// Redacts only values explicitly marked sensitive by their caller.
    ///
    /// Plain items are rendered as ordinary argv values without guessing
    /// whether they are options, assignments, or option values. Non-UTF-8
    /// sensitive items are masked from an opaque sentinel so their original
    /// bytes can never reach output. Items are pulled lazily and the iterator
    /// is not advanced after the diagnostic budget is exhausted.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime of argument values borrowed by the iterator.
    /// * `I` - Iterator source yielding borrowed [`ArgvItem`] values.
    ///
    /// # Parameters
    ///
    /// * `items` - Borrowed argv items with optional authoritative levels.
    ///
    /// # Returns
    ///
    /// A log-safe rendering in input order. Its completion is `Complete` only
    /// when the iterator's end was observed, `Truncated` when safe non-empty
    /// output represents omitted input or output, and `Exhausted` when no safe
    /// substitute fit.
    #[must_use]
    pub fn redact_items<'a, I>(&self, items: I) -> RedactedArgv
    where
        I: IntoIterator<Item = ArgvItem<'a>>,
    {
        let mut session = self.redactor.session();
        session.argv_with_mut(|argv| argv.redact_items(items))
    }

    /// Redacts explicit sensitive values and heuristically classified plain
    /// values.
    ///
    /// Explicit sensitivity always wins. Plain items recognize
    /// `--name value`, `--name=value`, `-name value`, `NAME=value`, and
    /// JVM-style `-Dname=value` properties. Compact options such as
    /// `-pSECRET` and shell payload syntax are not inferred. Callers must mark
    /// those values explicitly when they are sensitive. Because this is a
    /// safety heuristic rather than a command-specific parser, an option
    /// delimiter does not disable recognition in later wrapper or child-command
    /// segments. A non-UTF-8 plain item is masked at [`Sensitivity::Secret`]
    /// because it cannot be classified safely.
    /// Items are pulled lazily and the iterator is not advanced after the
    /// diagnostic budget is exhausted.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime of argument values borrowed by the iterator.
    /// * `I` - Iterator source yielding borrowed [`ArgvItem`] values.
    ///
    /// # Parameters
    ///
    /// * `items` - Borrowed argv items with optional authoritative levels.
    ///
    /// # Returns
    ///
    /// A log-safe rendering in input order. Its completion is `Complete` only
    /// when the iterator's end was observed, `Truncated` when safe non-empty
    /// output represents omitted input or output, and `Exhausted` when no safe
    /// substitute fit.
    #[must_use]
    pub fn redact_heuristically<'a, I>(&self, items: I) -> RedactedArgv
    where
        I: IntoIterator<Item = ArgvItem<'a>>,
    {
        let mut session = self.redactor.session();
        session.argv_with_mut(|argv| argv.redact_heuristically(items))
    }

    /// Renders an item while bounding any generated mask.
    ///
    /// # Parameters
    ///
    /// * `item` - Explicitly classified or plain argument item.
    /// * `max_output_bytes` - Maximum bytes retained from a generated mask.
    ///
    /// # Returns
    ///
    /// The rendered item and whether its mask was locally shortened.
    #[inline]
    pub(super) fn render_explicit_or_plain_bounded(
        &self,
        item: ArgvItem<'_>,
        max_output_bytes: usize,
    ) -> (String, bool) {
        match item.sensitivity() {
            Some(level) => self.mask_os_value_bounded(item.value(), level, max_output_bytes),
            None => (item.value().to_string_lossy().into_owned(), false),
        }
    }

    /// Masks an operating-system value with an explicit output ceiling.
    ///
    /// # Parameters
    ///
    /// * `value` - Argument value to mask without exposing invalid UTF-8.
    /// * `level` - Sensitivity selecting the configured mask policy.
    /// * `max_output_bytes` - Maximum bytes retained from the mask.
    ///
    /// # Returns
    ///
    /// The bounded mask and whether the configured replacement was shortened.
    #[inline]
    pub(super) fn mask_os_value_bounded(
        &self,
        value: &OsStr,
        level: Sensitivity,
        max_output_bytes: usize,
    ) -> (String, bool) {
        match value.to_str() {
            Some(value) => {
                let (masked, truncated) =
                    self.redactor
                        .policy()
                        .masking()
                        .mask_bounded_with_truncation(level, value, max_output_bytes);
                (masked.into_owned(), truncated)
            }
            None => self.mask_opaque_value_bounded(max_output_bytes),
        }
    }

    /// Redacts one plain item with a bounded mask ceiling.
    ///
    /// # Parameters
    ///
    /// * `value` - Plain argument to classify heuristically.
    /// * `pending_field` - Sensitive option awaiting its separate value.
    /// * `max_output_bytes` - Maximum bytes retained from a generated mask.
    ///
    /// # Returns
    ///
    /// The rendered item and whether its generated mask was shortened.
    pub(super) fn redact_plain_item_bounded(
        &self,
        value: &OsStr,
        pending_field: &mut Option<PendingField>,
        max_output_bytes: usize,
    ) -> (String, bool) {
        let Some(value) = value.to_str() else {
            *pending_field = Some(PendingField {
                field: String::new(),
                exact: false,
            });
            return self.mask_opaque_value_bounded(max_output_bytes);
        };

        let option = self.option_field(value);
        if let Some(pending) = pending_field.take() {
            if let Some((field, exact)) = option
                && self.option_is_sensitive(field, exact)
            {
                *pending_field = Some(PendingField {
                    field: field.to_owned(),
                    exact,
                });
            }
            if pending.field.is_empty() {
                return self.mask_opaque_value_bounded(max_output_bytes);
            }
            return self.mask_pending_value_bounded(&pending, value, max_output_bytes);
        }
        if let Some(value) = self.redact_assignment_bounded(value, max_output_bytes) {
            return value;
        }
        if let Some(value) = self.redact_inline_option_bounded(value, max_output_bytes) {
            return value;
        }
        if let Some(value) = self.redact_jvm_property_bounded(value, max_output_bytes) {
            return value;
        }
        if let Some((field, exact)) = option
            && self.option_is_sensitive(field, exact)
        {
            *pending_field = Some(PendingField {
                field: field.to_owned(),
                exact,
            });
        }
        (value.to_owned(), false)
    }

    /// Resolves sensitivity for one bare option token.
    ///
    /// # Parameters
    ///
    /// * `value` - Plain argument that may name an option.
    ///
    /// # Returns
    ///
    /// `Some(level)` for a configured option name, or `None` otherwise.
    #[inline]
    fn option_field<'a>(&self, value: &'a str) -> Option<(&'a str, bool)> {
        let name = option_name(value)?;
        if value.starts_with("--") {
            Some((name, false))
        } else {
            Some((name, true))
        }
    }

    /// Returns whether an option field must be treated as sensitive.
    fn option_is_sensitive(&self, field: &str, exact: bool) -> bool {
        if exact {
            self.redactor.policy().sensitivity_for_exact(field).is_some()
        } else {
            self.redactor.policy().sensitivity_for(field).is_some()
        }
    }

    /// Redacts an assignment while bounding any generated mask.
    ///
    /// Returns the rendered assignment and local mask-truncation flag when the
    /// assignment names a sensitive field, or `None` otherwise.
    fn redact_assignment_bounded(&self, value: &str, max_output_bytes: usize) -> Option<(String, bool)> {
        if value.starts_with('-') {
            return None;
        }
        let (name, raw_value) = value.split_once('=')?;
        if name.is_empty() {
            return None;
        }
        let (redacted, truncated) = self.mask_field_value_bounded(name, raw_value, max_output_bytes)?;
        Some((format!("{name}={redacted}"), truncated))
    }

    /// Redacts a plain `--name=value` token when its name is sensitive.
    ///
    /// # Parameters
    ///
    /// * `value` - Plain argument that may be an inline option.
    ///
    /// # Returns
    ///
    /// `Some((rendering, truncated))` for a sensitive long inline option, or
    /// `None` otherwise. Single-dash attached forms remain uninterpreted.
    fn redact_inline_option_bounded(&self, value: &str, max_output_bytes: usize) -> Option<(String, bool)> {
        if !value.starts_with("--") {
            return None;
        }
        let (left, raw_value) = value.split_once('=')?;
        let name = option_name(left)?;
        let (redacted, truncated) = self.mask_field_value_bounded(name, raw_value, max_output_bytes)?;
        Some((format!("{left}={redacted}"), truncated))
    }

    /// Redacts a JVM property while bounding any generated mask.
    ///
    /// Returns the rendered property and local mask-truncation flag when its
    /// field is sensitive, or `None` otherwise.
    fn redact_jvm_property_bounded(&self, value: &str, max_output_bytes: usize) -> Option<(String, bool)> {
        let property = value.strip_prefix("-D")?;
        let (name, raw_value) = property.split_once('=')?;
        if name.is_empty() {
            return None;
        }
        let (redacted, truncated) = self.mask_field_value_bounded(name, raw_value, max_output_bytes)?;
        Some((format!("-D{name}={redacted}"), truncated))
    }

    /// Masks one pending option value with a bounded mask ceiling.
    ///
    /// Returns the rendered value and whether its mask was locally shortened.
    fn mask_pending_value_bounded(
        &self,
        pending: &PendingField,
        value: &str,
        max_output_bytes: usize,
    ) -> (String, bool) {
        let resolved = if pending.exact {
            self.redactor.policy().resolve_field_exact(&pending.field)
        } else {
            self.redactor.policy().resolve_field(&pending.field)
        };
        match resolved {
            ResolvedField::Sensitive { sensitivity } => {
                let (masked, truncated) =
                    self.redactor
                        .policy()
                        .masking()
                        .mask_bounded_with_truncation(sensitivity, value, max_output_bytes);
                (masked.into_owned(), truncated)
            }
            ResolvedField::PassThrough => (value.to_owned(), false),
        }
    }

    /// Masks one classified field with a bounded mask ceiling.
    ///
    /// Returns a bounded mask and its truncation flag for a sensitive field,
    /// or `None` for pass-through fields.
    fn mask_field_value_bounded(&self, field: &str, value: &str, max_output_bytes: usize) -> Option<(String, bool)> {
        let resolved = self.redactor.policy().resolve_field(field);
        match resolved {
            ResolvedField::Sensitive { sensitivity } => {
                let (masked, truncated) =
                    self.redactor
                        .policy()
                        .masking()
                        .mask_bounded_with_truncation(sensitivity, value, max_output_bytes);
                Some((masked.into_owned(), truncated))
            }
            ResolvedField::PassThrough => None,
        }
    }

    /// Produces an opaque secret replacement with an explicit ceiling.
    ///
    /// # Parameters
    ///
    /// * `max_output_bytes` - Maximum bytes retained from the replacement.
    ///
    /// # Returns
    ///
    /// The bounded replacement and whether it is shorter than the configured
    /// complete opaque mask.
    #[inline(always)]
    pub(super) fn mask_opaque_value_bounded(&self, max_output_bytes: usize) -> (String, bool) {
        let masking = self.redactor.policy().masking();
        let complete_len = masking.mask_opaque(Sensitivity::Secret).len();
        let masked = masking.mask_opaque_bounded(Sensitivity::Secret, max_output_bytes);
        let truncated = masked.len() < complete_len;
        (masked, truncated)
    }
}

impl Default for ArgvRedactor {
    /// Creates an argv redactor from the current default policy snapshot.
    ///
    /// # Returns
    ///
    /// An argv redactor backed by [`Redactor::default`].
    #[inline(always)]
    fn default() -> Self {
        Self::new(Redactor::default())
    }
}

/// Returns an option name without its leading dashes.
///
/// # Parameters
///
/// * `value` - Argument token that may name an option.
///
/// # Returns
///
/// `Some(name)` for an option-looking token with a non-empty name, or `None`
/// otherwise.
#[inline]
fn option_name(value: &str) -> Option<&str> {
    if !value.starts_with('-') || value == "-" || value.contains('=') {
        return None;
    }
    let name = value.trim_start_matches('-');
    if name.is_empty() { None } else { Some(name) }
}
