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
    Redactor,
    Sensitivity,
};

use super::{
    ArgvItem,
    RedactedArgv,
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
        let mut input_budget =
            self.redactor.policy().diagnostic_budget().input_budget();
        self.redact_items_with_input_budget(items, &mut input_budget)
    }

    /// Redacts explicitly classified values using shared input accounting.
    ///
    /// The caller owns `input_budget` and may pass it to later diagnostic
    /// segments, ensuring the combined rendering never inspects more source
    /// bytes than the configured policy permits.
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
        let mut rendered =
            RedactedArgv::builder(self.redactor.policy().diagnostic_budget());
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
        let mut input_budget =
            self.redactor.policy().diagnostic_budget().input_budget();
        self.redact_heuristically_with_input_budget(items, &mut input_budget)
    }

    /// Redacts explicit and heuristic values using shared input accounting.
    ///
    /// The caller owns `input_budget` and may pass it to later diagnostic
    /// segments, ensuring the combined rendering never inspects more source
    /// bytes than the configured policy permits.
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
        let mut rendered =
            RedactedArgv::builder(self.redactor.policy().diagnostic_budget());
        let mut pending_sensitivity = None;

        for item in items {
            if !input_budget.reserve(item.value().as_encoded_bytes().len()) {
                let _ = rendered.push(TRUNCATED_ITEM);
                break;
            }
            if let Some(level) = item.sensitivity() {
                pending_sensitivity = None;
                if !rendered.push(&self.mask_os_value(item.value(), level)) {
                    break;
                }
                continue;
            }
            if !rendered.push(
                &self.redact_plain_item(item.value(), &mut pending_sensitivity),
            ) {
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
        pending_sensitivity: &mut Option<Sensitivity>,
    ) -> String {
        let Some(value) = value.to_str() else {
            let encoded = value.as_encoded_bytes();
            let may_take_separate_value =
                encoded.starts_with(b"-") && !encoded.contains(&b'=');
            *pending_sensitivity =
                may_take_separate_value.then_some(Sensitivity::Secret);
            return self.mask_opaque_value();
        };

        let option_sensitivity = self.option_sensitivity(value);
        if let Some(pending) = pending_sensitivity.take() {
            if let Some(level) = option_sensitivity {
                *pending_sensitivity = Some(level);
            }
            return self.mask_utf8_value(value, pending);
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
        if let Some(level) = option_sensitivity {
            *pending_sensitivity = Some(level);
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
    fn option_sensitivity(&self, value: &str) -> Option<Sensitivity> {
        let name = option_name(value)?;
        if value.starts_with("--") {
            self.redactor.policy().sensitivity_for(name)
        } else {
            self.redactor.policy().sensitivity_for_exact(name)
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
        let level = self.redactor.policy().sensitivity_for(name)?;
        let redacted = self.mask_utf8_value(raw_value, level);
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
        let level = self.redactor.policy().sensitivity_for(name)?;
        let redacted = self.mask_utf8_value(raw_value, level);
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
        let level = self.redactor.policy().sensitivity_for(name)?;
        let redacted = self.mask_utf8_value(raw_value, level);
        Some(format!("-D{name}={redacted}"))
    }

    /// Masks one valid UTF-8 value at an explicit sensitivity level.
    ///
    /// # Parameters
    ///
    /// * `value` - Valid UTF-8 value to mask.
    /// * `level` - Masking level to apply.
    ///
    /// # Returns
    ///
    /// The configured mask as an owned string.
    #[inline(always)]
    fn mask_utf8_value(&self, value: &str, level: Sensitivity) -> String {
        self.redactor
            .policy()
            .masking()
            .mask_bounded(level, value, self.mask_output_limit())
            .into_owned()
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
            .diagnostic_budget()
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
