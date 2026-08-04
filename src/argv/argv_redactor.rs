// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Explicit and heuristic argument-vector redaction.

use std::ffi::OsStr;

use crate::{
    DiagnosticInputBudget,
    RedactionSession,
    Redactor,
    Sensitivity,
    policy::ResolvedField,
};

use super::{
    ArgvItem,
    RedactedArgv,
    pending_field::PendingField,
    redacted_argv_builder::TRUNCATED_ITEM,
};

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
        let session = RedactionSession::diagnostic(self.redactor.policy());
        self.redact_items_with_session(items, &session)
    }

    /// Redacts explicitly classified values using shared input accounting.
    ///
    /// The caller owns `input_budget` and may pass it to later diagnostic
    /// segments, ensuring the combined rendering never inspects more source
    /// bytes than the configured policy permits.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime of argument values borrowed by the iterator.
    /// * `I` - Iterator source yielding borrowed [`ArgvItem`] values.
    ///
    /// # Parameters
    ///
    /// * `items` - Borrowed argv items with optional authoritative levels.
    /// * `input_budget` - Shared source-byte accounting for this diagnostic.
    ///
    /// # Returns
    ///
    /// A log-safe rendering in input order, ending with `<truncated>` when the
    /// next item cannot be inspected within the shared budget.
    pub fn redact_items_with_input_budget<'a, I>(
        &self,
        items: I,
        input_budget: &mut DiagnosticInputBudget,
    ) -> RedactedArgv
    where
        I: IntoIterator<Item = ArgvItem<'a>>,
    {
        let mut rendered = RedactedArgv::builder(
            self.redactor.policy().limits().diagnostic_event(),
        );
        for item in items {
            if !input_budget.reserve(item.value().as_encoded_bytes().len()) {
                let _ = rendered.push(TRUNCATED_ITEM);
                break;
            }
            if !rendered.push(&self.render_explicit_or_plain(item)) {
                break;
            }
        }
        rendered.finish()
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
        let session = RedactionSession::diagnostic(self.redactor.policy());
        self.redact_heuristically_with_session(items, &session)
    }

    /// Redacts explicit items while sharing cumulative input and output
    /// accounting with other diagnostic adapters.
    pub fn redact_items_with_session<'a, I>(
        &self,
        items: I,
        session: &RedactionSession<'_>,
    ) -> RedactedArgv
    where
        I: IntoIterator<Item = ArgvItem<'a>>,
    {
        self.render_with_session(items, session, |redactor, items, budget| {
            redactor.redact_items_with_input_budget(items, budget)
        })
    }

    /// Redacts explicit and heuristic items through a shared diagnostic
    /// session.
    pub fn redact_heuristically_with_session<'a, I>(
        &self,
        items: I,
        session: &RedactionSession<'_>,
    ) -> RedactedArgv
    where
        I: IntoIterator<Item = ArgvItem<'a>>,
    {
        self.render_with_session(items, session, |redactor, items, budget| {
            redactor.redact_heuristically_with_input_budget(items, budget)
        })
    }

    fn render_with_session<'a, I, F>(
        &self,
        items: I,
        session: &RedactionSession<'_>,
        render: F,
    ) -> RedactedArgv
    where
        I: IntoIterator<Item = ArgvItem<'a>>,
        F: FnOnce(&Self, I, &mut DiagnosticInputBudget) -> RedactedArgv,
    {
        let available = session.remaining_input_bytes();
        let mut input_budget = DiagnosticInputBudget::new(available);
        let result = render(self, items, &mut input_budget);
        let consumed =
            available.saturating_sub(input_budget.remaining_input_bytes());
        if input_budget.remaining_input_bytes() == 0 {
            let _ = session.consume_input(available);
        } else {
            let _ = session.consume_input(consumed);
        }
        if session.consume_output(result.as_log_safe_text().as_str().len()) {
            result
        } else {
            RedactedArgv::from_rendered(TRUNCATED_ITEM.to_owned())
        }
    }

    /// Redacts explicit and heuristic values using shared input accounting.
    ///
    /// The caller owns `input_budget` and may pass it to later diagnostic
    /// segments, ensuring the combined rendering never inspects more source
    /// bytes than the configured policy permits.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime of argument values borrowed by the iterator.
    /// * `I` - Iterator source yielding borrowed [`ArgvItem`] values.
    ///
    /// # Parameters
    ///
    /// * `items` - Borrowed argv items with optional authoritative levels.
    /// * `input_budget` - Shared source-byte accounting for this diagnostic.
    ///
    /// # Returns
    ///
    /// A log-safe rendering in input order, ending with `<truncated>` when the
    /// next item cannot be inspected within the shared budget.
    pub fn redact_heuristically_with_input_budget<'a, I>(
        &self,
        items: I,
        input_budget: &mut DiagnosticInputBudget,
    ) -> RedactedArgv
    where
        I: IntoIterator<Item = ArgvItem<'a>>,
    {
        let mut rendered = RedactedArgv::builder(
            self.redactor.policy().limits().diagnostic_event(),
        );
        let mut pending_field = None;

        for item in items {
            if !input_budget.reserve(item.value().as_encoded_bytes().len()) {
                let _ = rendered.push(TRUNCATED_ITEM);
                break;
            }
            if let Some(level) = item.sensitivity() {
                pending_field = None;
                if !rendered.push(&self.mask_os_value(item.value(), level)) {
                    break;
                }
                continue;
            }
            if !rendered
                .push(&self.redact_plain_item(item.value(), &mut pending_field))
            {
                break;
            }
        }
        rendered.finish()
    }

    /// Renders an item according to explicit sensitivity without heuristics.
    ///
    /// # Parameters
    ///
    /// * `item` - Item whose explicit metadata is authoritative.
    ///
    /// # Returns
    ///
    /// The masked or plain owned rendering.
    #[inline]
    fn render_explicit_or_plain(&self, item: ArgvItem<'_>) -> String {
        match item.sensitivity() {
            Some(level) => self.mask_os_value(item.value(), level),
            None => item.value().to_string_lossy().into_owned(),
        }
    }

    /// Masks an operating-system value without exposing invalid UTF-8 bytes.
    ///
    /// # Parameters
    ///
    /// * `value` - Operating-system value to mask.
    /// * `level` - Explicit masking level for valid UTF-8 input.
    ///
    /// # Returns
    ///
    /// The configured mask, using the secret opaque replacement when `value`
    /// is not valid UTF-8.
    #[inline]
    fn mask_os_value(&self, value: &OsStr, level: Sensitivity) -> String {
        match value.to_str() {
            Some(value) => self
                .redactor
                .policy()
                .masking()
                .mask_bounded(level, value, self.mask_output_limit())
                .into_owned(),
            None => self.mask_opaque_value(),
        }
    }

    /// Redacts one plain item while updating pending-value state.
    ///
    /// # Parameters
    ///
    /// * `value` - Plain operating-system argument to inspect.
    /// * `pending_sensitivity` - Level expected for the next separate value.
    ///
    /// # Returns
    ///
    /// The redacted owned rendering of `value`.
    fn redact_plain_item(
        &self,
        value: &OsStr,
        pending_field: &mut Option<PendingField>,
    ) -> String {
        let Some(value) = value.to_str() else {
            *pending_field = Some(PendingField {
                field: String::new(),
                exact: false,
            });
            return self.mask_opaque_value();
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
                return self.mask_opaque_value();
            }
            return self.mask_pending_value(&pending, value);
        }
        if let Some(value) = self.redact_assignment(value) {
            return value;
        }
        if let Some(value) = self.redact_inline_option(value) {
            return value;
        }
        if let Some(value) = self.redact_jvm_property(value) {
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

    /// Redacts a plain `NAME=value` token when its name is sensitive.
    ///
    /// # Parameters
    ///
    /// * `value` - Plain argument that may be an assignment.
    ///
    /// # Returns
    ///
    /// `Some(rendering)` for an assignment-like argument, or `None` otherwise.
    fn redact_assignment(&self, value: &str) -> Option<String> {
        if value.starts_with('-') {
            return None;
        }
        let (name, raw_value) = value.split_once('=')?;
        if name.is_empty() {
            return None;
        }
        let redacted = self.mask_field_value(name, raw_value)?;
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
    #[inline]
    fn redact_inline_option(&self, value: &str) -> Option<String> {
        if !value.starts_with("--") {
            return None;
        }
        let (left, raw_value) = value.split_once('=')?;
        let name = option_name(left)?;
        let redacted = self.mask_field_value(name, raw_value)?;
        Some(format!("{left}={redacted}"))
    }

    /// Redacts a JVM `-Dname=value` property when its name is sensitive.
    ///
    /// # Parameters
    ///
    /// * `value` - Plain argument that may be a JVM system property.
    ///
    /// # Returns
    ///
    /// `Some(rendering)` for a sensitive JVM property, or `None` otherwise.
    fn redact_jvm_property(&self, value: &str) -> Option<String> {
        let property = value.strip_prefix("-D")?;
        let (name, raw_value) = property.split_once('=')?;
        if name.is_empty() {
            return None;
        }
        let redacted = self.mask_field_value(name, raw_value)?;
        Some(format!("-D{name}={redacted}"))
    }

    fn mask_pending_value(
        &self,
        pending: &PendingField,
        value: &str,
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
                .mask_bounded(sensitivity, value, self.mask_output_limit())
                .into_owned(),
            ResolvedField::PassThrough => value.to_owned(),
        }
    }

    /// Masks one field value using its atomic field-resolution result.
    fn mask_field_value(&self, field: &str, value: &str) -> Option<String> {
        let resolved = self.redactor.policy().resolve_field(field);
        match resolved {
            ResolvedField::Sensitive { sensitivity } => Some(
                self.redactor
                    .policy()
                    .masking()
                    .mask_bounded(sensitivity, value, self.mask_output_limit())
                    .into_owned(),
            ),
            ResolvedField::PassThrough => None,
        }
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
            .mask_opaque_bounded(Sensitivity::Secret, self.mask_output_limit())
    }

    /// Returns the largest mask that can contribute to one argv diagnostic.
    ///
    /// # Returns
    ///
    /// The configured final diagnostic output limit in bytes.
    #[inline(always)]
    fn mask_output_limit(&self) -> usize {
        self.redactor
            .policy()
            .limits()
            .diagnostic_event()
            .max_output_bytes()
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
