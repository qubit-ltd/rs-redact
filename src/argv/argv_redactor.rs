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
#[must_use = "use the redactor to produce a safe argv rendering"]
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

    /// Redacts only values explicitly marked sensitive by their caller.
    ///
    /// Plain items are rendered as ordinary argv values without guessing
    /// whether they are options, assignments, or option values. Non-UTF-8
    /// sensitive items are masked from an opaque sentinel so their original
    /// bytes can never reach output.
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
    /// A log-safe rendering in input order.
    pub fn redact_items<'a, I>(&self, items: I) -> RedactedArgv
    where
        I: IntoIterator<Item = ArgvItem<'a>>,
    {
        let mut session = self.redactor.session();
        session.argv().redact_items(items)
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
    /// A log-safe rendering in input order.
    pub fn redact_heuristically<'a, I>(&self, items: I) -> RedactedArgv
    where
        I: IntoIterator<Item = ArgvItem<'a>>,
    {
        let mut session = self.redactor.session();
        session.argv().redact_heuristically(items)
    }

    /// Renders an item while bounding any generated mask.
    #[inline]
    pub(super) fn render_explicit_or_plain_bounded(
        &self,
        item: ArgvItem<'_>,
        max_output_bytes: usize,
    ) -> String {
        match item.sensitivity() {
            Some(level) => self.mask_os_value_bounded(
                item.value(),
                level,
                max_output_bytes,
            ),
            None => item.value().to_string_lossy().into_owned(),
        }
    }

    /// Masks an operating-system value with an explicit output ceiling.
    #[inline]
    pub(super) fn mask_os_value_bounded(
        &self,
        value: &OsStr,
        level: Sensitivity,
        max_output_bytes: usize,
    ) -> String {
        match value.to_str() {
            Some(value) => self
                .redactor
                .policy()
                .masking()
                .mask_bounded(level, value, max_output_bytes)
                .into_owned(),
            None => self.mask_opaque_value_bounded(max_output_bytes),
        }
    }

    /// Redacts one plain item with a bounded mask ceiling.
    pub(super) fn redact_plain_item_bounded(
        &self,
        value: &OsStr,
        pending_field: &mut Option<PendingField>,
        max_output_bytes: usize,
    ) -> String {
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
            return self.mask_pending_value_bounded(
                &pending,
                value,
                max_output_bytes,
            );
        }
        if let Some(value) =
            self.redact_assignment_bounded(value, max_output_bytes)
        {
            return value;
        }
        if let Some(value) =
            self.redact_inline_option_bounded(value, max_output_bytes)
        {
            return value;
        }
        if let Some(value) =
            self.redact_jvm_property_bounded(value, max_output_bytes)
        {
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
        value.to_owned()
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

    fn option_is_sensitive(&self, field: &str, exact: bool) -> bool {
        if exact {
            self.redactor
                .policy()
                .sensitivity_for_exact(field)
                .is_some()
        } else {
            self.redactor.policy().sensitivity_for(field).is_some()
        }
    }

    /// Redacts an assignment while bounding any generated mask.
    fn redact_assignment_bounded(
        &self,
        value: &str,
        max_output_bytes: usize,
    ) -> Option<String> {
        if value.starts_with('-') {
            return None;
        }
        let (name, raw_value) = value.split_once('=')?;
        if name.is_empty() {
            return None;
        }
        let redacted =
            self.mask_field_value_bounded(name, raw_value, max_output_bytes)?;
        Some(format!("{name}={redacted}"))
    }

    /// Redacts a plain `--name=value` token when its name is sensitive.
    ///
    /// # Parameters
    ///
    /// * `value` - Plain argument that may be an inline option.
    ///
    /// # Returns
    ///
    /// `Some(rendering)` for a sensitive long inline option, or `None`
    /// otherwise. Single-dash attached forms remain uninterpreted.
    /// Redacts an inline option while bounding any generated mask.
    fn redact_inline_option_bounded(
        &self,
        value: &str,
        max_output_bytes: usize,
    ) -> Option<String> {
        if !value.starts_with("--") {
            return None;
        }
        let (left, raw_value) = value.split_once('=')?;
        let name = option_name(left)?;
        let redacted =
            self.mask_field_value_bounded(name, raw_value, max_output_bytes)?;
        Some(format!("{left}={redacted}"))
    }

    /// Redacts a JVM property while bounding any generated mask.
    fn redact_jvm_property_bounded(
        &self,
        value: &str,
        max_output_bytes: usize,
    ) -> Option<String> {
        let property = value.strip_prefix("-D")?;
        let (name, raw_value) = property.split_once('=')?;
        if name.is_empty() {
            return None;
        }
        let redacted =
            self.mask_field_value_bounded(name, raw_value, max_output_bytes)?;
        Some(format!("-D{name}={redacted}"))
    }

    /// Masks one pending option value with a bounded mask ceiling.
    fn mask_pending_value_bounded(
        &self,
        pending: &PendingField,
        value: &str,
        max_output_bytes: usize,
    ) -> String {
        let resolved = if pending.exact {
            self.redactor.policy().resolve_field_exact(&pending.field)
        } else {
            self.redactor.policy().resolve_field(&pending.field)
        };
        match resolved {
            ResolvedField::Sensitive { sensitivity } => self
                .redactor
                .policy()
                .masking()
                .mask_bounded(sensitivity, value, max_output_bytes)
                .into_owned(),
            ResolvedField::PassThrough => value.to_owned(),
        }
    }

    /// Masks one classified field with a bounded mask ceiling.
    fn mask_field_value_bounded(
        &self,
        field: &str,
        value: &str,
        max_output_bytes: usize,
    ) -> Option<String> {
        let resolved = self.redactor.policy().resolve_field(field);
        match resolved {
            ResolvedField::Sensitive { sensitivity } => Some(
                self.redactor
                    .policy()
                    .masking()
                    .mask_bounded(sensitivity, value, max_output_bytes)
                    .into_owned(),
            ),
            ResolvedField::PassThrough => None,
        }
    }

    /// Produces an opaque secret replacement with an explicit ceiling.
    #[inline(always)]
    pub(super) fn mask_opaque_value_bounded(
        &self,
        max_output_bytes: usize,
    ) -> String {
        self.redactor
            .policy()
            .masking()
            .mask_opaque_bounded(Sensitivity::Secret, max_output_bytes)
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
