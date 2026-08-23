// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Restricted structured writer used by domain redaction implementations.
// qubit-style: allow multiple-public-types

use std::fmt;
use std::fmt::Debug;
use std::fmt::Write as _;

use crate::RedactionSession;
use crate::Sensitivity;
use crate::domain::Redact;
use crate::domain::RedactLevelValue;
use crate::policy::ResolvedField;

/// Restricted writer for one redaction operation.
///
/// Implementations use structural scopes to classify every field explicitly.
/// The writer borrows one transaction and never publishes intermediate text.
///
/// # Examples
///
/// ```
/// use qubit_redact::{Redact, RedactionWriter, Redactor, Sensitivity};
///
/// struct Credential(&'static str);
///
/// impl Redact for Credential {
///     fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
///         writer.record("Credential", |fields| {
///             fields.sensitive(Sensitivity::Secret, "token", || self.0);
///         });
///     }
/// }
///
/// let output = Redactor::standard().redact(&Credential("raw-token"));
/// assert!(!output.text().as_str().contains("raw-token"));
/// ```
///
/// ```compile_fail
/// use qubit_redact::{Redact, RedactionWriter};
///
/// struct Value;
/// impl Redact for Value {
///     fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
///         let _ = writer.redact_json_text("{\"token\":\"secret\"}");
///     }
/// }
/// ```
pub struct RedactionWriter<'session> {
    session: &'session mut RedactionSession,
}

impl<'session> RedactionWriter<'session> {
    /// Creates a writer backed by an existing diagnostic session.
    #[must_use]
    pub(crate) fn new(session: &'session mut RedactionSession) -> Self {
        Self { session }
    }

    /// Creates a writer that owns the root output admission for one value.
    pub(crate) fn new_root(session: &'session mut RedactionSession) -> Self {
        Self::new(session)
    }

    /// Writes a trusted static structural literal.
    #[inline]
    pub fn literal(&mut self, text: &'static str) {
        if self.session.domain_frame_is_truncated() {
            return;
        }
        self.write_fragment(text);
    }

    /// Writes explicitly trusted dynamic content without redaction.
    ///
    /// # Warning
    ///
    /// This method never consults field policy. It is only for content that
    /// the caller has independently established as safe to expose; sensitive
    /// values must be written through a redaction-aware field method instead.
    pub fn unredacted<T>(&mut self, value: &T) -> &mut Self
    where
        T: Debug + ?Sized,
    {
        if self.session.domain_frame_is_truncated() {
            return self;
        }
        if self.session.is_inspection() {
            return self;
        }
        self.write_debug(value);
        self
    }

    /// Writes a field without applying redaction policy.
    #[inline]
    pub fn unmarked<T>(&mut self, value: &T) -> &mut Self
    where
        T: Debug + ?Sized,
    {
        self.unredacted(value)
    }

    pub(crate) fn trim_trailing_separator(&mut self) {
        self.session.trim_domain_frame_separator();
    }

    /// Writes JSON text through the active transaction.
    ///
    /// This is intentionally private: structured redaction implementations
    /// must never receive unpublished JSON text before `finish()` publishes
    /// the surrounding transaction.
    #[cfg(feature = "json")]
    fn write_json_text(&mut self, value: &str) {
        if self.session.is_inspection() {
            crate::formats::json::inspection::inspect_text(self.session, value);
            return;
        }
        if !self.session.admit_input(value.len()) {
            self.truncate_without_output_limit();
            return;
        }
        // Structural admission happens before JSON redaction parses or walks
        // the value. A domain writer therefore cannot create a private JSON
        // traversal budget outside its parent transaction.
        let admitted = match crate::formats::json::admit_json_text_value(self.session, value) {
            Ok(value) => value,
            Err(crate::formats::json::JsonAdmissionError::Invalid) => {
                let allowance = self.session.remaining_output_bytes().min(self.remaining_output_bytes());
                let output = crate::formats::json::invalid_json_output(self.session.policy(), allowance);
                self.session.record_rendered_provenance(&output);
                self.write_debug(output.text());
                return;
            }
            Err(crate::formats::json::JsonAdmissionError::Limit) => {
                self.truncate_without_output_limit();
                return;
            }
        };
        let allowance = self.session.remaining_output_bytes().min(self.remaining_output_bytes());
        let output = crate::formats::json::redact_json_value_with_limit(self.session.policy(), &admitted, allowance);
        if output.completion() != crate::RedactionCompletion::Complete {
            self.truncate_without_output_limit();
        }
        self.session.record_rendered_provenance(&output);
        self.write_debug(output.text());
    }

    /// Writes a borrowed parsed JSON value as an unquoted JSON fragment.
    #[cfg(feature = "json")]
    fn write_json_value(&mut self, value: &serde_json::Value) {
        if self.session.is_inspection() {
            crate::formats::json::inspection::inspect_borrowed_value(self.session, value);
            return;
        }
        if !self.session.admit_json_value(value) {
            self.truncate_without_output_limit();
            return;
        }
        let allowance = self.session.remaining_output_bytes().min(self.remaining_output_bytes());
        let output = crate::formats::json::redact_json_value_with_limit(self.session.policy(), value, allowance);
        if output.completion() != crate::RedactionCompletion::Complete {
            self.truncate_without_output_limit();
        }
        self.session.record_rendered_provenance(&output);
        self.write_fragment(output.text());
    }

    /// Writes a named record through a field scope.
    pub fn record<F>(&mut self, name: &'static str, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionFields<'writer, 'session>),
    {
        self.write_field_structure(name, " { ", " }", configure);
    }

    /// Writes a named tuple through a field scope.
    pub fn tuple<F>(&mut self, name: &'static str, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionFields<'writer, 'session>),
    {
        self.write_field_structure(name, "(", ")", configure);
    }

    /// Writes a bracketed sequence through an item scope.
    pub fn sequence<F>(&mut self, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionItems<'writer, 'session>),
    {
        self.write_item_structure("", "[", "]", configure);
    }

    /// Writes a braced map through an entry scope.
    pub fn map<F>(&mut self, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionEntries<'writer, 'session>),
    {
        self.write_entry_structure("", "{ ", " }", configure);
    }

    /// Writes a named enum variant through a field scope.
    pub fn variant<F>(&mut self, enum_name: &'static str, variant_name: &'static str, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionFields<'writer, 'session>),
    {
        self.write_fragment(enum_name);
        self.write_fragment("::");
        self.write_field_structure(variant_name, " { ", " }", configure);
    }

    /// Finishes the writer and reports whether its bounded frame omitted text.
    #[must_use]
    pub(crate) fn finish_with_completion(self) -> (String, bool, bool) {
        self.session.finish_domain_frame()
    }

    /// Writes one bounded structured frame and accounts for its domain node
    /// and output bytes.
    fn write_field_structure<F>(
        &mut self,
        name: &'static str,
        opening: &'static str,
        closing: &'static str,
        configure: F,
    ) where
        F: for<'writer> FnOnce(&mut RedactionFields<'writer, 'session>),
    {
        if !self.session.begin_domain_value() {
            self.truncate_without_output_limit();
            return;
        }
        self.write_fragment(name);
        self.write_fragment(opening);
        if self.can_write() {
            let mut fields = RedactionFields {
                writer: self,
                named: opening == " { ",
            };
            configure(&mut fields);
        }
        if self.can_write() {
            self.trim_trailing_separator();
            self.write_fragment(closing);
        }
        self.session.leave_domain_value();
    }

    fn write_item_structure<F>(
        &mut self,
        name: &'static str,
        opening: &'static str,
        closing: &'static str,
        configure: F,
    ) where
        F: for<'writer> FnOnce(&mut RedactionItems<'writer, 'session>),
    {
        if !self.session.begin_domain_value() {
            self.truncate_without_output_limit();
            return;
        }
        self.write_fragment(name);
        self.write_fragment(opening);
        if self.can_write() {
            configure(&mut RedactionItems { writer: self });
        }
        if self.can_write() {
            self.trim_trailing_separator();
            self.write_fragment(closing);
        }
        self.session.leave_domain_value();
    }

    fn write_entry_structure<F>(
        &mut self,
        name: &'static str,
        opening: &'static str,
        closing: &'static str,
        configure: F,
    ) where
        F: for<'writer> FnOnce(&mut RedactionEntries<'writer, 'session>),
    {
        if !self.session.begin_domain_value() {
            self.truncate_without_output_limit();
            return;
        }
        self.write_fragment(name);
        self.write_fragment(opening);
        if self.can_write() {
            configure(&mut RedactionEntries { writer: self });
        }
        if self.can_write() {
            self.trim_trailing_separator();
            self.write_fragment(closing);
        }
        self.session.leave_domain_value();
    }

    /// Closes this writer after it has actually exceeded its output allowance.
    fn truncate_for_output_limit(&mut self) {
        self.session.mark_domain_frame_output_limit_reached();
        self.truncate_without_output_limit();
    }

    /// Closes this writer without inventing output-limit provenance.
    ///
    /// Structural and input admission failures already record their specific
    /// cause in the shared session. If their fallback marker itself cannot
    /// fit, [`Self::write_fragment`] records the additional output limit.
    fn truncate_without_output_limit(&mut self) {
        self.session.truncate_domain_frame_without_output_limit();
    }

    /// Appends `text` only while its final log-escaped representation fits.
    ///
    /// Returning an error from the bounded `fmt::Write` adapter terminates a
    /// caller's `Debug` implementation before it can format later chunks.
    fn write_fragment(&mut self, text: &str) -> bool {
        self.session.write_domain_fragment(text)
    }

    pub(crate) fn write_debug<T>(&mut self, value: &T)
    where
        T: Debug + ?Sized,
    {
        if self.session.is_inspection() {
            return;
        }
        let mut formatter = BoundedDebugWriter { writer: self };
        let _ = write!(&mut formatter, "{value:?}");
    }

    /// Writes an already-accessed dynamic value using the selected policy
    /// level.
    fn write_masked_debug<T>(&mut self, level: Sensitivity, value: &T)
    where
        T: Debug + ?Sized,
    {
        if self.session.is_inspection() {
            self.session.observe_sensitivity(level);
            return;
        }
        if matches!(level, Sensitivity::High | Sensitivity::Secret) {
            let masked = self
                .session
                .policy()
                .masking()
                .mask_opaque_bounded(level, self.remaining_output_bytes());
            self.write_debug(&masked);
            return;
        }
        let raw_limit = self.remaining_output_bytes();
        let (raw, raw_truncated) = bounded_debug(value, raw_limit);
        let (masked, mask_truncated) =
            self.session
                .policy()
                .masking()
                .mask_bounded_with_truncation(level, &raw, self.remaining_output_bytes());
        self.write_debug(masked.as_ref());
        if raw_truncated || mask_truncated {
            self.truncate_for_output_limit();
        }
    }

    pub(crate) fn write_level_scalar<T>(&mut self, level: Sensitivity, value: &T)
    where
        T: Debug + ?Sized,
    {
        if self.session.policy().is_disabled() {
            self.write_debug(value);
        } else {
            self.write_masked_debug(level, value);
        }
    }

    pub(crate) fn level_tuple<F>(&mut self, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionItems<'writer, 'session>),
    {
        self.write_item_structure("", "(", ")", configure);
    }

    #[inline]
    fn can_write(&self) -> bool {
        !self.session.domain_frame_is_truncated() && self.remaining_output_bytes() > 0
    }

    #[inline]
    fn remaining_output_bytes(&self) -> usize {
        self.session.remaining_domain_frame_output_bytes()
    }
}

/// `fmt::Write` adapter that stops a `Debug` formatter at the writer's final
/// escaped-output ceiling instead of first materializing an unbounded string.
struct BoundedDebugWriter<'writer, 'session> {
    writer: &'writer mut RedactionWriter<'session>,
}

impl fmt::Write for BoundedDebugWriter<'_, '_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self.writer.write_fragment(value) {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

/// Field scope for a record or tuple writer.
pub struct RedactionFields<'writer, 'session> {
    writer: &'writer mut RedactionWriter<'session>,
    named: bool,
}

impl<'writer, 'session> RedactionFields<'writer, 'session> {
    /// Writes a field that the implementer has explicitly classified as safe
    /// to expose without redaction.
    ///
    /// # Warning
    ///
    /// This method does not consult runtime field policy and executes
    /// `access`. Use it only for fields that are intentionally unredacted.
    /// Every field requiring redaction must use [`Self::sensitive`] or another
    /// redaction-aware writer method instead.
    pub fn unredacted<T, F>(&mut self, name: &str, access: F) -> &mut Self
    where
        T: Debug,
        F: FnOnce() -> T,
    {
        if !self.admit_field() {
            self.write_field_truncated();
            return self;
        }
        if self.writer.session.is_inspection() {
            return self;
        }
        self.write_prefix(name);
        if !self.writer.can_write() {
            return self;
        }
        let value = access();
        self.writer.write_debug(&value);
        self.writer.write_fragment(", ");
        self
    }

    /// Writes a field that has no explicit redaction mode.
    #[inline]
    pub fn unmarked<T, F>(&mut self, name: &str, access: F) -> &mut Self
    where
        T: Debug,
        F: FnOnce() -> T,
    {
        self.unredacted(name, access)
    }

    /// Writes a field with an explicit minimum sensitivity.
    ///
    /// The effective sensitivity is the stronger of `level` and the active
    /// policy's classification for `name`. A policy may therefore raise this
    /// field's protection, but can never lower the implementer's explicit
    /// minimum. When that effective level is [`Sensitivity::High`] or
    /// [`Sensitivity::Secret`], `access` is not evaluated.
    pub fn sensitive<T, F>(&mut self, level: Sensitivity, name: &str, access: F) -> &mut Self
    where
        T: Debug,
        F: FnOnce() -> T,
    {
        if !self.admit_field() {
            self.write_field_truncated();
            return self;
        }
        if self.writer.session.policy().is_disabled() {
            return self.unredacted(name, access);
        }
        let effective_level = self
            .writer
            .session
            .policy()
            .sensitivity_for(name)
            .map_or(level, |policy_level| policy_level.max(level));
        if self.writer.session.is_inspection() {
            self.writer.session.observe_sensitivity(effective_level);
            return self;
        }
        self.write_prefix(name);
        if !self.writer.can_write() {
            return self;
        }
        if matches!(effective_level, Sensitivity::High | Sensitivity::Secret) {
            let value = self
                .writer
                .session
                .policy()
                .masking()
                .mask_opaque_bounded(effective_level, self.writer.remaining_output_bytes());
            self.writer.write_debug(&value);
        } else {
            let raw_limit = self.writer.remaining_output_bytes();
            let (raw, raw_truncated) = bounded_debug(&access(), raw_limit);
            let (value, mask_truncated) = self.writer.session.policy().masking().mask_bounded_with_truncation(
                effective_level,
                &raw,
                self.writer.remaining_output_bytes(),
            );
            self.writer.write_debug(value.as_ref());
            if raw_truncated || mask_truncated {
                self.writer.truncate_for_output_limit();
            }
        }
        self.writer.write_fragment(", ");
        self
    }

    /// Writes a sealed level-capable value while preserving its recursive
    /// container shape and masking every scalar leaf independently.
    #[doc(hidden)]
    pub fn sensitive_value<T>(&mut self, level: Sensitivity, name: &str, value: &T) -> &mut Self
    where
        T: RedactLevelValue + ?Sized,
    {
        if !self.admit_field() {
            self.write_field_truncated();
            return self;
        }
        let effective_level = self
            .writer
            .session
            .policy()
            .sensitivity_for(name)
            .map_or(level, |policy_level| policy_level.max(level));
        if self.writer.session.is_inspection() {
            if !self.writer.session.policy().is_disabled() {
                self.writer.session.observe_sensitivity(effective_level);
            }
            return self;
        }
        self.write_prefix(name);
        if self.writer.can_write() {
            value.write_redacted_level(self.writer, effective_level);
            self.writer.write_fragment(", ");
        }
        self
    }

    /// Redacts JSON text for a named field through this shared transaction.
    #[cfg(feature = "json")]
    pub fn json(&mut self, name: &str, value: &str) -> &mut Self {
        if !self.admit_field() {
            self.write_field_truncated();
            return self;
        }
        if self.writer.session.policy().is_disabled() {
            return self.unredacted(name, || value);
        }
        self.write_prefix(name);
        if !self.writer.can_write() {
            return self;
        }
        self.writer.write_json_text(value);
        self.writer.write_fragment(", ");
        self
    }

    /// Writes a borrowed parsed JSON value without cloning or modifying it.
    #[cfg(feature = "json")]
    pub fn json_value(&mut self, name: &str, value: &serde_json::Value) -> &mut Self {
        if !self.admit_field() {
            self.write_field_truncated();
            return self;
        }
        self.write_prefix(name);
        if self.writer.can_write() {
            self.writer.write_json_value(value);
            self.writer.write_fragment(", ");
        }
        self
    }

    /// Writes a supported JSON string variant through its sealed capability.
    #[cfg(feature = "json")]
    #[doc(hidden)]
    pub fn json_text_value<T>(&mut self, name: &str, value: &T) -> &mut Self
    where
        T: super::RedactJsonValue + ?Sized,
    {
        value.write_redacted_json(self, name);
        self
    }

    /// Writes a nested domain value through the current session.
    pub fn nested<T>(&mut self, name: &str, value: &T) -> &mut Self
    where
        T: Redact + ?Sized,
    {
        if !self.admit_field() {
            self.write_field_truncated();
            return self;
        }
        if self.writer.session.policy().is_disabled() {
            self.write_prefix(name);
            value.write_redacted(self.writer);
            self.writer.write_fragment(", ");
            return self;
        }
        self.write_prefix(name);
        if !self.writer.can_write() {
            return self;
        }
        value.write_redacted(self.writer);
        self.writer.write_fragment(", ");
        self
    }

    /// Writes admitted entries from a supported text-keyed map.
    ///
    /// Each entry is admitted before the iterator advances. Sensitive keys use
    /// the active runtime policy; keys not selected by that policy retain their
    /// debug representation.
    pub(crate) fn map_entries<I, K, V>(&mut self, name: &str, entries: I) -> &mut Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str> + Debug,
        V: RedactLevelValue,
    {
        if !self.admit_field() {
            self.write_field_truncated();
            return self;
        }
        if self.writer.session.policy().is_disabled() {
            self.write_prefix(name);
            if !self.writer.can_write() {
                return self;
            }
            self.writer.write_fragment("{");
            let mut entries = entries.into_iter();
            while let Some((key, value)) = entries.next() {
                if !self.admit_item() {
                    self.write_field_truncated();
                    break;
                }
                self.writer.write_debug(key.as_ref());
                self.writer.write_fragment(": ");
                self.writer.write_debug(&value);
                if entries.size_hint().1 != Some(0) {
                    self.writer.write_fragment(", ");
                }
            }
            self.writer.write_fragment("}");
            return self;
        }
        self.write_prefix(name);
        if !self.writer.can_write() {
            return self;
        }
        self.writer.write_fragment("{");
        let mut entries = entries.into_iter();
        loop {
            if entries.size_hint().1 == Some(0) {
                break;
            }
            if !self.writer.session.preflight_collection_item() {
                self.write_field_truncated();
                break;
            }
            let Some((key, value)) = entries.next() else {
                break;
            };
            if !self.admit_item() {
                self.write_field_truncated();
                break;
            }
            let key = key.as_ref();
            if self.writer.session.is_inspection() {
                if let ResolvedField::Sensitive { sensitivity } = self.writer.session.policy().resolve_field(key) {
                    self.writer.session.observe_sensitivity(sensitivity);
                }
                continue;
            }
            self.writer.write_debug(key);
            self.writer.write_fragment(": ");
            match self.writer.session.policy().resolve_field(key) {
                ResolvedField::Sensitive { sensitivity } => {
                    value.write_redacted_level(self.writer, sensitivity);
                }
                ResolvedField::PassThrough => self.writer.write_debug(&value),
            }
            self.writer.write_fragment(", ");
            if !self.writer.can_write() {
                break;
            }
        }
        if self.writer.can_write() {
            self.writer.trim_trailing_separator();
            self.writer.write_fragment("}");
            self.writer.write_fragment(", ");
        }
        self
    }

    /// Writes a supported map field through its sealed capability.
    pub fn map<T>(&mut self, name: &str, value: &T) -> &mut Self
    where
        T: super::RedactMapValue,
    {
        value.write_redacted_map(self, name);
        self
    }

    /// Writes a supported map field through its sealed capability.
    #[doc(hidden)]
    pub fn map_value<T>(&mut self, name: &str, value: &T) -> &mut Self
    where
        T: super::RedactMapValue,
    {
        self.map(name, value)
    }

    /// Omits a field while redaction is enabled and restores it when disabled.
    pub fn skipped<T, F>(&mut self, name: &str, access: F) -> &mut Self
    where
        T: Debug,
        F: FnOnce() -> T,
    {
        if self.writer.session.policy().is_disabled() {
            self.unredacted(name, access)
        } else {
            self
        }
    }

    /// Returns whether the next field may be inspected.
    #[must_use]
    fn admit_field(&mut self) -> bool {
        if self.writer.session.domain_frame_is_truncated() || !self.writer.can_write() {
            return false;
        }
        self.writer.session.admit_domain_field()
    }

    #[inline]
    fn admit_item(&mut self) -> bool {
        !self.writer.session.domain_frame_is_truncated() && self.writer.session.admit_domain_collection_item()
    }

    fn write_prefix(&mut self, name: &str) {
        if self.named {
            self.writer.write_fragment(name);
            self.writer.write_fragment(": ");
        }
    }

    fn write_field_truncated(&mut self) {
        if !self.writer.session.domain_frame_is_truncated() {
            if self.named {
                self.writer.write_fragment("...: <truncated>");
            } else {
                self.writer.write_fragment("<truncated>");
            }
            self.writer.truncate_without_output_limit();
        }
    }
}

/// Item-only scope for a sequence writer.
pub struct RedactionItems<'writer, 'session> {
    writer: &'writer mut RedactionWriter<'session>,
}

impl<'writer, 'session> RedactionItems<'writer, 'session> {
    /// Writes one explicitly unredacted sequence item.
    ///
    /// # Warning
    ///
    /// This method emits the accessed value without consulting field policy.
    /// Use it only for data independently established as safe to expose;
    /// sensitive values must use [`Self::sensitive_item`].
    pub fn unredacted_item<T, F>(&mut self, access: F) -> &mut Self
    where
        T: Debug,
        F: FnOnce() -> T,
    {
        if !self.admit_item() {
            self.write_truncated();
            return self;
        }
        if self.writer.session.is_inspection() {
            return self;
        }
        self.writer.write_debug(&access());
        self.writer.write_fragment(", ");
        self
    }

    /// Writes one explicitly sensitive sequence item.
    pub fn sensitive_item<T, F>(&mut self, level: Sensitivity, access: F) -> &mut Self
    where
        T: Debug,
        F: FnOnce() -> T,
    {
        if !self.admit_item() {
            self.write_truncated();
            return self;
        }
        if self.writer.session.is_inspection() {
            self.writer.session.observe_sensitivity(level);
            return self;
        }
        if matches!(level, Sensitivity::High | Sensitivity::Secret) {
            let value = self
                .writer
                .session
                .policy()
                .masking()
                .mask_opaque_bounded(level, self.writer.remaining_output_bytes());
            self.writer.write_debug(&value);
        } else {
            self.writer.write_masked_debug(level, &access());
        }
        self.writer.write_fragment(", ");
        self
    }

    pub(crate) fn level_value<T>(&mut self, value: &T, level: Sensitivity) -> &mut Self
    where
        T: RedactLevelValue + ?Sized,
    {
        if !self.admit_item() {
            self.write_truncated();
            return self;
        }
        value.write_redacted_level(self.writer, level);
        self.writer.write_fragment(", ");
        self
    }

    /// Writes one nested domain value as a sequence item.
    pub fn nested_item<T>(&mut self, value: &T) -> &mut Self
    where
        T: Redact + ?Sized,
    {
        if !self.admit_item() {
            self.write_truncated();
            return self;
        }
        value.write_redacted(self.writer);
        self.writer.write_fragment(", ");
        self
    }

    fn admit_item(&mut self) -> bool {
        !self.writer.session.domain_frame_is_truncated() && self.writer.session.admit_domain_collection_item()
    }

    fn write_truncated(&mut self) {
        if !self.writer.session.domain_frame_is_truncated() {
            self.writer.write_fragment("<truncated>");
            self.writer.truncate_without_output_limit();
        }
    }
}

/// Entry-only scope for a map writer.
pub struct RedactionEntries<'writer, 'session> {
    writer: &'writer mut RedactionWriter<'session>,
}

impl<'writer, 'session> RedactionEntries<'writer, 'session> {
    /// Writes one explicitly unredacted map entry.
    ///
    /// # Warning
    ///
    /// This method emits the accessed value without consulting field policy.
    /// Use it only for data independently established as safe to expose;
    /// sensitive values must use [`Self::sensitive_entry`].
    pub fn unredacted_entry<T, F>(&mut self, name: &str, access: F) -> &mut Self
    where
        T: Debug,
        F: FnOnce() -> T,
    {
        if !self.admit_entry() {
            self.write_truncated();
            return self;
        }
        if self.writer.session.is_inspection() {
            return self;
        }
        self.write_prefix(name);
        self.writer.write_debug(&access());
        self.writer.write_fragment(", ");
        self
    }

    /// Writes one explicitly sensitive map entry.
    pub fn sensitive_entry<T, F>(&mut self, level: Sensitivity, name: &str, access: F) -> &mut Self
    where
        T: Debug,
        F: FnOnce() -> T,
    {
        if !self.admit_entry() {
            self.write_truncated();
            return self;
        }
        let effective_level = self
            .writer
            .session
            .policy()
            .sensitivity_for(name)
            .map_or(level, |policy_level| policy_level.max(level));
        if self.writer.session.is_inspection() {
            self.writer.session.observe_sensitivity(effective_level);
            return self;
        }
        self.write_prefix(name);
        if matches!(effective_level, Sensitivity::High | Sensitivity::Secret) {
            let value = self
                .writer
                .session
                .policy()
                .masking()
                .mask_opaque_bounded(effective_level, self.writer.remaining_output_bytes());
            self.writer.write_debug(&value);
        } else {
            self.writer.write_masked_debug(effective_level, &access());
        }
        self.writer.write_fragment(", ");
        self
    }

    /// Writes one nested map entry through the parent transaction.
    pub fn nested_entry<T>(&mut self, name: &str, value: &T) -> &mut Self
    where
        T: Redact + ?Sized,
    {
        if !self.admit_entry() {
            self.write_truncated();
            return self;
        }
        self.write_prefix(name);
        value.write_redacted(self.writer);
        self.writer.write_fragment(", ");
        self
    }

    fn admit_entry(&mut self) -> bool {
        !self.writer.session.domain_frame_is_truncated() && self.writer.session.admit_domain_collection_item()
    }

    fn write_prefix(&mut self, name: &str) {
        self.writer.write_fragment(name);
        self.writer.write_fragment(": ");
    }

    fn write_truncated(&mut self) {
        if !self.writer.session.domain_frame_is_truncated() {
            self.writer.write_fragment("...: <truncated>");
            self.writer.truncate_without_output_limit();
        }
    }
}

/// Captures a `Debug` representation without allowing its formatter to grow
/// an intermediate string beyond the caller's bounded need.
fn bounded_debug<T>(value: &T, maximum: usize) -> (String, bool)
where
    T: Debug + ?Sized,
{
    let mut writer = BoundedCapture::new(maximum);
    let _ = write!(&mut writer, "{value:?}");
    writer.finish()
}

struct BoundedCapture {
    output: String,
    maximum: usize,
    truncated: bool,
}

impl BoundedCapture {
    fn new(maximum: usize) -> Self {
        Self {
            // `maximum` is an admission limit, not an allocation request.
            output: String::new(),
            maximum,
            truncated: false,
        }
    }

    fn finish(self) -> (String, bool) {
        (self.output, self.truncated)
    }
}

impl fmt::Write for BoundedCapture {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let mut end = 0;
        for (index, character) in value.char_indices() {
            let next = index + character.len_utf8();
            if next > self.maximum.saturating_sub(self.output.len()) {
                self.truncated = true;
                return Err(fmt::Error);
            }
            end = next;
        }
        self.output.push_str(&value[..end]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::RedactionWriter;
    use crate::Redact;
    use crate::Redactor;

    struct Nested;

    impl Redact for Nested {
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            writer.record("Nested", |fields| {
                fields.unredacted("id", || 7_u8);
            });
        }
    }

    struct Container;

    impl Redact for Container {
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            writer.record("Container", |fields| {
                fields.nested("nested", &Nested);
            });
        }
    }

    /// Nested values render through the borrowed writer and the active
    /// transaction.
    #[test]
    fn nested_values_use_the_active_writer_transaction() {
        let output = Redactor::standard().redact(&Container);

        assert!(output.text().as_str().contains("Nested { id: 7 }"));
        assert_eq!(output.summary().usage().output_bytes(), output.text().as_str().len());
    }

    #[cfg(feature = "json")]
    struct JsonContainer;

    #[cfg(feature = "json")]
    impl Redact for JsonContainer {
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            writer.record("JsonContainer", |fields| {
                fields.json("payload", "{invalid json");
            });
        }
    }

    /// JSON emitted from a domain writer must use the active session for input
    /// accounting and retain parser provenance in that transaction summary.
    #[cfg(feature = "json")]
    #[test]
    fn writer_json_uses_the_active_session_summary() {
        let output = Redactor::standard().text_composer().value(&JsonContainer).finish();

        assert_eq!(output.summary().usage().presented_input_bytes(), "{invalid json".len());
        assert!(output.summary().reasons().contains(crate::RedactionReason::InvalidJson));
    }

    /// A JSON value emitted by a domain writer must spend the same structural
    /// budget as the enclosing domain transaction. The structural reason must
    /// remain visible instead of being relabelled as output exhaustion.
    #[cfg(feature = "json")]
    #[test]
    fn writer_json_uses_shared_structure_budget_and_preserves_its_reason() {
        let policy = crate::RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_depth(1);
            })
            .expect("the limit draft should build")
            .build()
            .expect("the policy should build");
        let output = Redactor::new(policy)
            .text_composer()
            .value(&JsonContainerWithValidNestedValue)
            .finish();

        assert_eq!(output.summary().completion(), crate::RedactionCompletion::Truncated);
        assert!(
            output
                .summary()
                .reasons()
                .contains(crate::RedactionReason::DepthLimitReached)
        );
        assert!(
            !output
                .summary()
                .reasons()
                .contains(crate::RedactionReason::OutputLimitReached)
        );
        assert!(output.text().as_str().contains("<truncated>"));
    }

    /// Individually resolved domain values must retain the structural reason
    /// too; their per-item summary is derived from the same writer state.
    #[cfg(feature = "json")]
    #[test]
    fn writer_json_handle_preserves_shared_structure_reason() {
        let policy = crate::RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_depth(1);
            })
            .expect("the limit draft should build")
            .build()
            .expect("the policy should build");
        let mut batch = Redactor::new(policy).batch();
        let handle = batch.redact_value(&JsonContainerWithValidNestedValue);
        let output = batch.finish();
        let item = output.resolve(handle).expect("the handle should resolve");

        assert!(
            item.summary()
                .reasons()
                .contains(crate::RedactionReason::DepthLimitReached)
        );
        assert!(
            !item
                .summary()
                .reasons()
                .contains(crate::RedactionReason::OutputLimitReached)
        );
    }

    #[cfg(feature = "json")]
    struct JsonContainerWithValidNestedValue;

    #[cfg(feature = "json")]
    impl Redact for JsonContainerWithValidNestedValue {
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            writer.record("JsonContainer", |fields| {
                fields.json("payload", r#"{"outer":{"inner":"value"}}"#);
            });
        }
    }
}
