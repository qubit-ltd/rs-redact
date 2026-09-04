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
    /// Transaction session receiving classified output and accounting.
    pub(super) session: &'session mut dyn RuntimeSession,
}

impl<'session> RedactionWriter<'session> {
    /// Creates a writer backed by an existing diagnostic session.
    #[must_use]
    pub(crate) fn new(session: &'session mut dyn RuntimeSession) -> Self {
        Self { session }
    }

    /// Creates a writer that owns the root output admission for one value.
    pub(crate) fn new_root(session: &'session mut dyn RuntimeSession) -> Self {
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
    /// This method is an explicit trust-boundary bypass: it never consults
    /// field policy, even when the active policy is strict. It is only for
    /// content that the caller has independently established as safe to expose.
    /// Never pass credentials, user-controlled diagnostic data, or a value
    /// whose classification depends on runtime policy; use a redaction-aware
    /// field method instead.
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
    #[inline]
    pub fn unmarked<T>(&mut self, value: &T) -> &mut Self
    where
        T: Debug + ?Sized,
    {
        self.unredacted(value)
    }

    /// Removes the trailing separator from the active domain frame.
    pub(crate) fn trim_trailing_separator(&mut self) {
        self.session.trim_domain_frame_separator();
    }

    /// Writes JSON text through the active transaction.
    ///
    /// This is intentionally private: structured redaction implementations
    /// must never receive unpublished JSON text before `finish()` publishes
    /// the surrounding transaction.
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

    /// Writes exactly one field without a nominal record or tuple wrapper.
    ///
    /// This is intended for transparent domain newtypes. The configured field
    /// still passes through the ordinary classified field operations and the
    /// same admission limits as a structured value.
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

    /// Writes one named sequence-like domain structure.
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

    /// Writes one named map-like domain structure.
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
    pub(super) fn truncate_for_output_limit(&mut self) {
        self.session.mark_domain_frame_output_limit_reached();
        self.truncate_without_output_limit();
    }

    /// Closes this writer without inventing output-limit provenance.
    ///
    /// Structural and input admission failures already record their specific
    /// cause in the shared session. If their fallback marker itself cannot
    /// fit, [`Self::write_fragment`] records the additional output limit.
    pub(super) fn truncate_without_output_limit(&mut self) {
        self.session.truncate_domain_frame_without_output_limit();
    }

    /// Appends `text` only while its final log-escaped representation fits.
    ///
    /// Returning an error from the bounded `fmt::Write` adapter terminates a
    /// caller's `Debug` implementation before it can format later chunks.
    pub(super) fn write_fragment(&mut self, text: &str) -> bool {
        self.session.write_domain_fragment(text)
    }

    /// Streams a debug representation into the bounded output session.
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
    pub(crate) fn level_tuple<F>(&mut self, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionItems<'writer, 'session>),
    {
        self.write_item_structure("", "(", ")", configure);
    }

    /// Returns whether the active frame can accept another fragment.
    #[inline]
    pub(super) fn can_write(&self) -> bool {
        !self.session.domain_frame_is_truncated() && self.remaining_output_bytes() > 0
    }

    /// Returns bytes still available to the active domain frame.
    #[inline]
    pub(super) fn remaining_output_bytes(&self) -> usize {
        self.session.remaining_domain_frame_output_bytes()
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
