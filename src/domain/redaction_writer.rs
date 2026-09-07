// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Restricted structured writer used by domain redaction implementations.

use std::fmt::Debug;
use std::fmt::Write as _;

use crate::Sensitivity;
use crate::domain::RedactionEntries;
use crate::domain::RedactionFields;
use crate::domain::RedactionItems;
use crate::domain::internal::bounded_capture::bounded_debug;
use crate::domain::internal::bounded_debug_writer::BoundedDebugWriter;
use crate::runtime::runtime_session::RuntimeSession;

/// Restricted writer for one redaction operation.
///
/// Implementations use structural scopes to classify every field explicitly.
/// The writer borrows one transaction and never publishes intermediate text.
///
/// # Type Parameters
///
/// - `'session`: Exclusive borrow of the transaction receiving this value.
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
/// let output = Redactor::standard().redact_text(&Credential("raw-token"));
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
    /// Transaction session receiving classified output and accounting.
    pub(super) session: &'session mut dyn RuntimeSession,
}

impl<'session> RedactionWriter<'session> {
    /// Creates a writer backed by an existing diagnostic session.
    ///
    /// # Parameters
    ///
    /// - `session`: Existing transaction that owns the output frame and
    ///   budgets.
    ///
    /// # Returns
    ///
    /// A writer borrowing that transaction.
    #[must_use]
    #[inline(always)]
    pub(crate) fn new(session: &'session mut dyn RuntimeSession) -> Self {
        Self { session }
    }

    /// Creates a writer that owns the root output admission for one value.
    ///
    /// # Parameters
    ///
    /// - `session`: Transaction whose root domain operation has been admitted.
    ///
    /// # Returns
    ///
    /// A writer sharing the transaction's root output allowance.
    #[must_use]
    #[inline(always)]
    pub(crate) fn new_root(session: &'session mut dyn RuntimeSession) -> Self {
        Self::new(session)
    }

    /// Writes a trusted static structural literal.
    ///
    /// # Parameters
    ///
    /// - `text`: Trusted static structure; omitted after the frame closes.
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
    /// This method is an explicit trust-boundary bypass: it never consults
    /// field policy, even when the active policy is strict. It is only for
    /// content that the caller has independently established as safe to expose.
    /// Never pass credentials, user-controlled diagnostic data, or a value
    /// whose classification depends on runtime policy; use a redaction-aware
    /// field method instead.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Possibly unsized value rendered with `Debug`.
    ///
    /// # Parameters
    ///
    /// - `value`: Caller-verified safe value; formatting is skipped during
    ///   inspection.
    ///
    /// # Returns
    ///
    /// This writer for subsequent writes.
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
    ///
    /// # Warning
    ///
    /// This is the semantic alias used for an intentionally unmarked field and
    /// has the same trust-boundary requirements as [`Self::unredacted`].
    ///
    /// # Type Parameters
    ///
    /// - `T`: Possibly unsized value rendered with `Debug`.
    ///
    /// # Parameters
    ///
    /// - `value`: Caller-verified safe value with no policy classification.
    ///
    /// # Returns
    ///
    /// This writer for subsequent writes.
    #[inline(always)]
    pub fn unmarked<T>(&mut self, value: &T) -> &mut Self
    where
        T: Debug + ?Sized,
    {
        self.unredacted(value)
    }

    /// Writes a named record through a field scope.
    ///
    /// # Type Parameters
    ///
    /// - `F`: Callback accepting the scope for any temporary writer borrow.
    ///
    /// # Parameters
    ///
    /// - `name`: Trusted static type label; an empty label emits no name.
    /// - `configure`: One-shot callback that writes through the borrowed scope.
    #[inline(always)]
    pub fn record<F>(&mut self, name: &'static str, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionFields<'writer, 'session>),
    {
        self.write_field_structure(name, " { ", " }", configure);
    }

    /// Writes a named tuple through a field scope.
    ///
    /// # Type Parameters
    ///
    /// - `F`: Callback accepting the scope for any temporary writer borrow.
    ///
    /// # Parameters
    ///
    /// - `name`: Trusted static type label; an empty label emits no name.
    /// - `configure`: One-shot callback that writes through the borrowed scope.
    #[inline(always)]
    pub fn tuple<F>(&mut self, name: &'static str, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionFields<'writer, 'session>),
    {
        self.write_field_structure(name, "(", ")", configure);
    }

    /// Writes exactly one field without a nominal record or tuple wrapper.
    ///
    /// This is intended for transparent domain newtypes. The configured field
    /// still passes through the ordinary classified field operations and the
    /// same admission limits as a structured value.
    ///
    /// # Type Parameters
    ///
    /// - `F`: Callback accepting the scope for any temporary writer borrow.
    ///
    /// # Parameters
    ///
    /// - `configure`: One-shot callback that writes through the borrowed scope.
    #[inline]
    pub fn transparent<F>(&mut self, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionFields<'writer, 'session>),
    {
        let mut fields = RedactionFields {
            writer: self,
            named: false,
        };
        configure(&mut fields);
        self.trim_trailing_separator();
    }

    /// Writes a bracketed sequence through an item scope.
    ///
    /// # Type Parameters
    ///
    /// - `F`: Callback accepting the scope for any temporary writer borrow.
    ///
    /// # Parameters
    ///
    /// - `configure`: One-shot callback that writes through the borrowed scope.
    #[inline(always)]
    pub fn sequence<F>(&mut self, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionItems<'writer, 'session>),
    {
        self.write_item_structure("", "[", "]", configure);
    }

    /// Writes a braced map through an entry scope.
    ///
    /// # Type Parameters
    ///
    /// - `F`: Callback accepting the scope for any temporary writer borrow.
    ///
    /// # Parameters
    ///
    /// - `configure`: One-shot callback that writes through the borrowed scope.
    #[inline(always)]
    pub fn map<F>(&mut self, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionEntries<'writer, 'session>),
    {
        self.write_entry_structure("", "{ ", " }", configure);
    }

    /// Writes a named enum variant through a field scope.
    ///
    /// # Type Parameters
    ///
    /// - `F`: Callback accepting the scope for any temporary writer borrow.
    ///
    /// # Parameters
    ///
    /// - `enum_name`: Trusted static enum label.
    /// - `variant_name`: Trusted static variant label.
    /// - `configure`: One-shot callback that writes through the borrowed scope.
    #[inline]
    pub fn variant<F>(&mut self, enum_name: &'static str, variant_name: &'static str, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionFields<'writer, 'session>),
    {
        self.write_fragment(enum_name);
        self.write_fragment("::");
        self.write_field_structure(variant_name, " { ", " }", configure);
    }

    /// Returns whether the active frame can accept another fragment.
    ///
    /// # Returns
    ///
    /// Whether the frame remains open and has at least one output byte
    /// available.
    #[must_use]
    #[inline]
    pub(super) fn can_write(&self) -> bool {
        !self.session.domain_frame_is_truncated() && self.remaining_output_bytes() > 0
    }

    /// Returns bytes still available to the active domain frame.
    ///
    /// # Returns
    ///
    /// The remaining escaped-output byte allowance for the current frame.
    #[must_use]
    #[inline(always)]
    pub(super) fn remaining_output_bytes(&self) -> usize {
        self.session.remaining_domain_frame_output_bytes()
    }

    /// Removes the trailing separator from the active domain frame.
    #[inline(always)]
    pub(crate) fn trim_trailing_separator(&mut self) {
        self.session.trim_domain_frame_separator();
    }

    /// Writes JSON text through the active transaction.
    ///
    /// This is intentionally private: structured redaction implementations
    /// must never receive unpublished JSON text before `finish()` publishes
    /// the surrounding transaction.
    ///
    /// # Parameters
    ///
    /// - `value`: Raw JSON text charged to this transaction before parsing.
    #[cfg(feature = "json")]
    pub(super) fn write_json_text(&mut self, value: &str) {
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
    ///
    /// # Parameters
    ///
    /// - `value`: Parsed JSON whose payload and structure share the active
    ///   budget.
    #[cfg(feature = "json")]
    pub(super) fn write_json_value(&mut self, value: &serde_json::Value) {
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

    /// Finishes the writer and reports whether its bounded frame omitted text.
    ///
    /// # Returns
    ///
    /// The owned frame text, whether any frame content was omitted, and whether
    /// the frame exceeded its output allowance. Finishing resets the local
    /// frame.
    #[must_use]
    #[inline(always)]
    pub(crate) fn finish_with_completion(self) -> (String, bool, bool) {
        self.session.finish_domain_frame()
    }

    /// Closes this writer after it has actually exceeded its output allowance.
    #[inline]
    pub(super) fn truncate_for_output_limit(&mut self) {
        self.session.mark_domain_frame_output_limit_reached();
        self.truncate_without_output_limit();
    }

    /// Closes this writer without inventing output-limit provenance.
    ///
    /// Structural and input admission failures already record their specific
    /// cause in the shared session. If their fallback marker itself cannot
    /// fit, [`Self::write_fragment`] records the additional output limit.
    #[inline(always)]
    pub(super) fn truncate_without_output_limit(&mut self) {
        self.session.truncate_domain_frame_without_output_limit();
    }

    /// Appends `text` only while its final log-escaped representation fits.
    ///
    /// The bounded `fmt::Write` adapter translates rejection into an error,
    /// allowing a caller's `Debug` implementation to stop formatting.
    ///
    /// # Parameters
    ///
    /// - `text`: Fragment to append under the active escaped-output allowance.
    ///
    /// # Returns
    ///
    /// `true` if the complete fragment was accepted; `false` if the frame is
    /// closed or the fragment cannot fit. Rejection records truncation.
    #[inline(always)]
    pub(super) fn write_fragment(&mut self, text: &str) -> bool {
        self.session.write_domain_fragment(text)
    }

    /// Streams a debug representation into the bounded output session.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Possibly unsized value rendered with `Debug`.
    ///
    /// # Parameters
    ///
    /// - `value`: Borrowed value; formatting is skipped during inspection.
    #[inline]
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
    ///
    /// # Type Parameters
    ///
    /// - `T`: Possibly unsized value rendered with `Debug`.
    ///
    /// # Parameters
    ///
    /// - `level`: Sensitivity selected by the caller.
    /// - `value`: Borrowed value; formatting is skipped during inspection.
    pub(super) fn write_masked_debug<T>(&mut self, level: Sensitivity, value: &T)
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

    /// Writes a scalar using the supplied sensitivity level.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Possibly unsized value rendered with `Debug`.
    ///
    /// # Parameters
    ///
    /// - `level`: Sensitivity selected by the caller.
    /// - `value`: Borrowed value; formatting is skipped during inspection.
    #[inline]
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

    /// Writes a tuple whose items carry explicit sensitivities.
    ///
    /// # Type Parameters
    ///
    /// - `F`: Callback accepting the scope for any temporary writer borrow.
    ///
    /// # Parameters
    ///
    /// - `configure`: One-shot callback that writes through the borrowed scope.
    #[inline(always)]
    pub(crate) fn level_tuple<F>(&mut self, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionItems<'writer, 'session>),
    {
        self.write_item_structure("", "(", ")", configure);
    }

    /// Writes one bounded structured frame and accounts for its domain node
    /// and output bytes.
    ///
    /// # Type Parameters
    ///
    /// - `F`: Callback accepting the scope for any temporary writer borrow.
    ///
    /// # Parameters
    ///
    /// - `name`: Trusted static type label; an empty label emits no name.
    /// - `opening`: Trusted opening punctuation.
    /// - `closing`: Trusted closing punctuation, emitted only while the frame
    ///   is open.
    /// - `configure`: One-shot callback that writes through the borrowed scope.
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

    /// Writes one named sequence-like domain structure.
    ///
    /// # Type Parameters
    ///
    /// - `F`: Callback accepting the scope for any temporary writer borrow.
    ///
    /// # Parameters
    ///
    /// - `name`: Trusted static type label; an empty label emits no name.
    /// - `opening`: Trusted opening punctuation.
    /// - `closing`: Trusted closing punctuation, emitted only while the frame
    ///   is open.
    /// - `configure`: One-shot callback that writes through the borrowed scope.
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
            configure(&mut RedactionItems {
                writer: self,
                admitted_item: false,
            });
        }
        if self.can_write() {
            self.trim_trailing_separator();
            self.write_fragment(closing);
        }
        self.session.leave_domain_value();
    }

    /// Writes one named map-like domain structure.
    ///
    /// # Type Parameters
    ///
    /// - `F`: Callback accepting the scope for any temporary writer borrow.
    ///
    /// # Parameters
    ///
    /// - `name`: Trusted static type label; an empty label emits no name.
    /// - `opening`: Trusted opening punctuation.
    /// - `closing`: Trusted closing punctuation, emitted only while the frame
    ///   is open.
    /// - `configure`: One-shot callback that writes through the borrowed scope.
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
            configure(&mut RedactionEntries {
                writer: self,
                admitted_entry: false,
            });
        }
        if self.can_write() {
            self.trim_trailing_separator();
            self.write_fragment(closing);
        }
        self.session.leave_domain_value();
    }
}
