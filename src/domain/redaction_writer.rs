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
use crate::policy::ResolvedField;

/// Restricted writer for one redaction operation.
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
        self.write_debug(value);
        self
    }

    /// Returns the immutable policy used by this writer.
    #[must_use]
    #[inline(always)]
    pub fn policy(&self) -> &crate::RedactionPolicy {
        self.session.policy()
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
        if !self.session.admit_input(value.len()) {
            self.truncate_without_output_limit();
            return;
        }
        // Structural admission happens before JSON redaction parses or walks
        // the value. A domain writer therefore cannot create a private JSON
        // traversal budget outside its parent transaction.
        if !crate::formats::json::admit_json_text_structure(self.session, value) {
            self.truncate_without_output_limit();
            return;
        }
        let allowance = self.session.remaining_output_bytes().min(self.remaining_output_bytes());
        let output = crate::formats::json::redact_json_text_with_limit(self.session.policy(), value, allowance);
        if output.summary().completion() != crate::RedactionCompletion::Complete {
            self.truncate_without_output_limit();
        }
        self.session.record_format_provenance(*output.summary());
        self.write_debug(output.text().as_str());
    }

    /// Writes a named record through a field scope.
    pub fn record<F>(&mut self, name: &'static str, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionFields<'writer, 'session>),
    {
        self.write_structured(name, " { ", " }", configure);
    }

    /// Writes a named tuple through a field scope.
    pub fn tuple<F>(&mut self, name: &'static str, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionFields<'writer, 'session>),
    {
        self.write_structured(name, "(", ")", configure);
    }

    /// Writes a bracketed sequence through a field scope.
    pub fn list<F>(&mut self, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionFields<'writer, 'session>),
    {
        self.write_structured("", "[", "]", configure);
    }

    /// Writes a bracketed sequence through an item scope.
    pub fn sequence<F>(&mut self, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionFields<'writer, 'session>),
    {
        self.write_structured("", "[", "]", configure);
    }

    /// Writes a braced map through an entry scope.
    pub fn map<F>(&mut self, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionFields<'writer, 'session>),
    {
        self.write_structured("", "{ ", " }", configure);
    }

    /// Writes a named enum variant through a field scope.
    pub fn variant<F>(&mut self, enum_name: &'static str, variant_name: &'static str, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionFields<'writer, 'session>),
    {
        self.write_fragment(enum_name);
        self.write_fragment("::");
        self.write_structured(variant_name, " { ", " }", configure);
    }

    /// Writes a unit variant or unit struct.
    pub fn unit(&mut self, name: &'static str) {
        self.write_fragment(name);
    }

    /// Finishes the writer and reports whether its bounded frame omitted text.
    #[must_use]
    pub(crate) fn finish_with_completion(self) -> (String, bool, bool) {
        self.session.finish_domain_frame()
    }

    /// Writes one bounded structured frame and accounts for its domain node
    /// and output bytes.
    fn write_structured<F>(&mut self, name: &'static str, opening: &'static str, closing: &'static str, configure: F)
    where
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
        if self.session.domain_frame_is_truncated() {
            return;
        }
        const MARKER: &str = "<truncated>";
        let output_limit = self.session.remaining_output_bytes();
        let marker_bytes = MARKER.len().min(output_limit);
        self.session
            .truncate_domain_frame_to(output_limit.saturating_sub(marker_bytes));
        self.session.append_domain_frame_fragment(&MARKER[..marker_bytes]);
        self.session.mark_domain_frame_truncated();
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
        let mut formatter = BoundedDebugWriter { writer: self };
        let _ = write!(&mut formatter, "{value:?}");
    }

    /// Writes an already-accessed dynamic value using the selected policy
    /// level.
    fn write_masked_debug<T>(&mut self, level: Sensitivity, value: &T)
    where
        T: Debug + ?Sized,
    {
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
        self.write_prefix(name);
        if !self.writer.can_write() {
            return self;
        }
        let value = access();
        self.writer.write_debug(&value);
        self.writer.write_fragment(", ");
        self
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
        let effective_level = self
            .writer
            .session
            .policy()
            .sensitivity_for(name)
            .map_or(level, |policy_level| policy_level.max(level));
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

    /// Writes one explicitly unredacted sequence item.
    pub fn unredacted_item<T, F>(&mut self, access: F) -> &mut Self
    where
        T: Debug,
        F: FnOnce() -> T,
    {
        if !self.admit_item() {
            self.write_field_truncated();
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
        self.sensitive(level, "", access)
    }

    /// Writes one explicitly unredacted map entry.
    pub fn unredacted_entry<T, F>(&mut self, name: &str, access: F) -> &mut Self
    where
        T: Debug,
        F: FnOnce() -> T,
    {
        self.unredacted(name, access)
    }

    /// Writes one explicitly sensitive map entry.
    pub fn sensitive_entry<T, F>(&mut self, level: Sensitivity, name: &str, access: F) -> &mut Self
    where
        T: Debug,
        F: FnOnce() -> T,
    {
        self.sensitive(level, name, access)
    }

    /// Writes one nested map entry through the parent transaction.
    pub fn nested_entry<T>(&mut self, name: &str, value: &T) -> &mut Self
    where
        T: Redact + ?Sized,
    {
        self.nested(name, value)
    }

    /// Redacts JSON text for a named field through this shared transaction.
    #[cfg(feature = "json")]
    pub fn json(&mut self, name: &str, value: &str) -> &mut Self {
        if !self.admit_field() {
            self.write_field_truncated();
            return self;
        }
        self.write_prefix(name);
        if !self.writer.can_write() {
            return self;
        }
        self.writer.write_json_text(value);
        self.writer.write_fragment(", ");
        self
    }

    /// Writes one nested domain value as a tuple or sequence item.
    pub fn nested_item<T>(&mut self, value: &T) -> &mut Self
    where
        T: Redact + ?Sized,
    {
        if !self.admit_item() {
            self.write_field_truncated();
            return self;
        }
        value.write_redacted(self.writer);
        self.writer.write_fragment(", ");
        self
    }

    /// Writes a nested bracketed sequence inside the current structure.
    pub fn list<F>(&mut self, configure: F) -> &mut Self
    where
        F: for<'nested> FnOnce(&mut RedactionFields<'nested, 'session>),
    {
        self.writer.write_structured("", "[", "]", configure);
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
        self.write_prefix(name);
        if !self.writer.can_write() {
            return self;
        }
        value.write_redacted(self.writer);
        self.writer.write_fragment(", ");
        self
    }

    /// Writes a text-keyed map whose values are classified by their own keys.
    ///
    /// Each entry is admitted before the iterator advances. Sensitive keys use
    /// the active runtime policy; keys not selected by that policy retain their
    /// debug representation.
    pub fn map<I, K, V>(&mut self, name: &str, entries: I) -> &mut Self
    where
        I: IntoIterator<Item = (K, V)>,
        I::IntoIter: ExactSizeIterator,
        K: AsRef<str> + Debug,
        V: Debug,
    {
        if !self.admit_field() {
            self.write_field_truncated();
            return self;
        }
        self.write_prefix(name);
        if !self.writer.can_write() {
            return self;
        }
        self.writer.write_fragment("{");
        let mut entries = entries.into_iter();
        while entries.len() != 0 {
            if !self.admit_item() {
                self.write_field_truncated();
                break;
            }
            let Some((key, value)) = entries.next() else {
                break;
            };
            let key = key.as_ref();
            self.writer.write_debug(key);
            self.writer.write_fragment(": ");
            match self.writer.session.policy().resolve_field(key) {
                ResolvedField::Sensitive { sensitivity } => {
                    self.writer.write_masked_debug(sensitivity, &value);
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

    /// Nested values render through the borrowed writer instead of
    /// materializing a legacy lazy redaction result with its own path.
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
        let mut session = Redactor::standard().session();
        let output = session.value(&JsonContainer).finish();

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
        let mut session = Redactor::new(policy).session();

        let output = session.value(&JsonContainerWithValidNestedValue).finish();

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
        let mut session = Redactor::new(policy).session();
        let handle = session.redact_value(&JsonContainerWithValidNestedValue);
        let output = session.finish();
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
