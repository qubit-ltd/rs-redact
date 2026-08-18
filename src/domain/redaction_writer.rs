// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Restricted structured writer used by domain redaction implementations.
// qubit-style: allow multiple-public-types

use std::fmt::Debug;
use std::fmt::Write as _;

use crate::RedactionSession;
use crate::Sensitivity;
use crate::domain::Redact;
use crate::domain::RedactMapValue;
use crate::domain::RedactedMapResult;
use crate::domain::RedactedResult;
use crate::policy::DomainTraversalAdmission;

/// Restricted writer for one redaction operation.
pub struct RedactionWriter<'session, 'policy> {
    output: String,
    session: &'session mut RedactionSession<'policy>,
    field_truncated: bool,
    frame_start: usize,
    frame_limit: usize,
    root_admitted: bool,
}

impl<'session, 'policy> RedactionWriter<'session, 'policy> {
    /// Creates a writer backed by an existing diagnostic session.
    #[must_use]
    pub(crate) fn new(session: &'session mut RedactionSession<'policy>) -> Self {
        let frame_limit = usize::MAX;
        Self {
            output: if frame_limit == usize::MAX {
                String::new()
            } else {
                String::with_capacity(frame_limit)
            },
            session,
            field_truncated: false,
            frame_start: 0,
            frame_limit,
            root_admitted: false,
        }
    }

    /// Creates a writer that owns the root output admission for one value.
    pub(crate) fn new_root(session: &'session mut RedactionSession<'policy>) -> Self {
        let mut writer = Self::new(session);
        writer.root_admitted = true;
        writer
    }

    /// Writes a trusted static structural literal.
    #[inline]
    pub fn literal(&mut self, text: &'static str) {
        if self.field_truncated {
            return;
        }
        self.output.push_str(text);
        self.mark_frame_overflow();
    }

    /// Writes trusted text whose lifetime is shorter than the writer call.
    #[inline]
    pub fn text(&mut self, text: &str) {
        if self.field_truncated {
            return;
        }
        self.output.push_str(text);
        self.mark_frame_overflow();
    }

    /// Returns the immutable policy used by this writer.
    #[must_use]
    #[inline(always)]
    pub const fn policy(&self) -> &'policy crate::RedactionPolicy {
        self.session.policy()
    }

    pub(crate) fn session_mut(&mut self) -> &mut RedactionSession<'policy> {
        self.session
    }

    /// Creates an eagerly rendered nested domain view using this writer's
    /// independent traversal context.
    #[must_use]
    pub fn redacted<'a, T>(&mut self, value: &'a T) -> RedactedResult<'a, T>
    where
        T: Redact + ?Sized,
    {
        RedactedResult::new(value, self.session)
    }

    /// Creates an eagerly rendered map view using this writer's policy.
    #[must_use]
    pub fn redacted_map<'a, M, K, V>(&mut self, value: &'a M) -> RedactedMapResult<'a, M, K, V>
    where
        M: crate::domain::RedactMapValue<K, V> + ?Sized,
        K: ?Sized,
        V: ?Sized,
    {
        RedactedMapResult::new(value, self.session)
    }

    #[cfg(feature = "json")]
    pub fn redact_json_text(&mut self, value: &str) -> crate::RedactedText {
        crate::formats::json::JsonRedactor::new(self.policy().clone())
            .redact_text(value)
            .into_log_safe_text()
    }

    /// Returns whether this writer has no room for another fragment.
    #[must_use]
    #[inline(always)]
    pub fn is_exhausted(&self) -> bool {
        self.field_truncated
    }

    /// Writes a named record through a field scope.
    pub fn record<F>(&mut self, name: &str, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionFields<'writer, 'session, 'policy>),
    {
        self.write_structured(name, " { ", " }", configure);
    }

    /// Writes a named tuple through a field scope.
    pub fn tuple<F>(&mut self, name: &str, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionFields<'writer, 'session, 'policy>),
    {
        self.write_structured(name, "(", ")", configure);
    }

    /// Writes a bracketed sequence through a field scope.
    pub fn list<F>(&mut self, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionFields<'writer, 'session, 'policy>),
    {
        self.write_structured("", "[", "]", configure);
    }

    /// Writes a unit variant or unit struct.
    pub fn unit(&mut self, name: &str) {
        self.output.push_str(name);
        self.mark_frame_overflow();
        self.mark_frame_overflow();
    }

    /// Writes one already-redacted value through the current session.
    pub fn render<T, F>(&mut self, render: F)
    where
        T: Debug,
        F: FnOnce(&mut RedactionWriter<'_, 'policy>) -> T,
    {
        if !self.session.begin_domain_value() {
            self.output.push_str("<truncated>");
            return;
        }
        let max_output_bytes = usize::MAX;
        let start = self.output.len();
        let rendered = format!("{:?}", render(self));
        self.output.push_str(&rendered);
        let rendered_len = rendered.len();
        if rendered_len > max_output_bytes {
            self.truncate_with_marker(start, max_output_bytes);
        }
        self.session.leave_domain_value();
    }

    /// Finishes the writer and returns output whose bytes were charged to the
    /// shared session.
    #[must_use]
    pub(crate) fn finish(mut self) -> String {
        if self.root_admitted {
            let rendered_len = self.output.len();
            if rendered_len > self.frame_limit {
                self.truncate_with_marker(0, self.frame_limit);
            }
        }
        self.output
    }

    /// Writes one bounded structured frame and accounts for its domain node
    /// and output bytes.
    fn write_structured<F>(&mut self, name: &str, opening: &str, closing: &str, configure: F)
    where
        F: for<'writer> FnOnce(&mut RedactionFields<'writer, 'session, 'policy>),
    {
        if !self.session.begin_domain_value() {
            self.output.push_str("<truncated>");
            return;
        }
        let max_output_bytes = usize::MAX;
        let start = self.output.len();
        let previous_frame = (self.frame_start, self.frame_limit);
        self.frame_start = start;
        self.frame_limit = max_output_bytes;
        self.output.push_str(name);
        self.output.push_str(opening);
        {
            let mut fields = RedactionFields {
                writer: self,
                named: opening == " { ",
            };
            configure(&mut fields);
        }
        if self.output.ends_with(", ") {
            self.output.truncate(self.output.len() - 2);
        }
        self.output.push_str(closing);
        let rendered_len = self.output.len().saturating_sub(start);
        if rendered_len > max_output_bytes {
            self.truncate_with_marker(start, max_output_bytes);
        }
        self.session.leave_domain_value();
        (self.frame_start, self.frame_limit) = previous_frame;
    }

    fn truncate_with_marker(&mut self, start: usize, maximum: usize) {
        const MARKER: &str = "<truncated>";
        let marker_bytes = maximum.min(MARKER.len());
        let content_limit = maximum.saturating_sub(marker_bytes);
        self.output
            .truncate(floor_char_boundary(&self.output, start.saturating_add(content_limit)));
        self.output.push_str(&MARKER[..marker_bytes]);
    }

    /// Marks the active frame after its output ceiling is crossed.
    ///
    /// Replacement is deferred until the frame closes so collection callers
    /// can stop visiting later values first.
    #[inline]
    fn mark_frame_overflow(&mut self) {
        if self.output.len().saturating_sub(self.frame_start) > self.frame_limit {
            self.field_truncated = true;
        }
    }
}

/// Field scope for a record or tuple writer.
pub struct RedactionFields<'writer, 'session, 'policy> {
    writer: &'writer mut RedactionWriter<'session, 'policy>,
    named: bool,
}

impl<'writer, 'session, 'policy> RedactionFields<'writer, 'session, 'policy> {
    /// Writes a field using its ordinary debug representation.
    pub fn field<T, F>(&mut self, name: &str, access: F) -> &mut Self
    where
        T: Debug,
        F: FnOnce() -> T,
    {
        if !self.admit_field() {
            self.write_field_truncated();
            return self;
        }
        self.write_prefix(name);
        write!(self.writer.output, "{:?}", access()).expect("writing to an in-memory String cannot fail");
        self.writer.output.push_str(", ");
        self.writer.mark_frame_overflow();
        self
    }

    /// Writes a field with an explicit minimum sensitivity.
    pub fn sensitive<T, F>(&mut self, level: Sensitivity, name: &str, access: F) -> &mut Self
    where
        T: Debug,
        F: FnOnce() -> T,
    {
        if !self.admit_field() {
            self.write_field_truncated();
            return self;
        }
        let value = if matches!(level, Sensitivity::High | Sensitivity::Secret) {
            self.writer.session.policy().masking().mask_opaque(level).to_owned()
        } else {
            let raw = format!("{:?}", access());
            self.writer.session.redact_at(level, &raw).into_owned()
        };
        self.write_prefix(name);
        self.writer.output.push_str(&format!("{value:?}"));
        self.writer.output.push_str(", ");
        self.writer.mark_frame_overflow();
        self
    }

    /// Writes a field whose redacted value is produced with the shared
    /// session.
    pub fn value<T, F>(&mut self, name: &str, render: F) -> &mut Self
    where
        T: Debug,
        F: FnOnce(&mut RedactionWriter<'_, 'policy>) -> T,
    {
        if !self.admit_field() {
            self.write_field_truncated();
            return self;
        }
        let rendered = format!("{:?}", render(self.writer));
        self.write_prefix(name);
        self.writer.output.push_str(&rendered);
        self.writer.output.push_str(", ");
        self.writer.mark_frame_overflow();
        self
    }

    /// Writes an optional value while preserving its `Some`/`None` shape.
    pub fn optional_value<T, F>(&mut self, name: &str, value: &Option<T>, render: F) -> &mut Self
    where
        T: Debug,
        F: FnOnce(&T, &mut RedactionWriter<'_, 'policy>) -> String,
    {
        if !self.admit_field() {
            self.write_field_truncated();
            return self;
        }
        self.write_prefix(name);
        match value {
            Some(value) => {
                let rendered = render(value, self.writer);
                self.writer.output.push_str("Some(");
                self.writer.output.push_str(&rendered);
                self.writer.output.push(')');
            }
            None => self.writer.output.push_str("None"),
        }
        self.writer.output.push_str(", ");
        self.writer.mark_frame_overflow();
        self
    }

    /// Writes one tuple item through the shared session.
    pub fn item<T, F>(&mut self, render: F) -> &mut Self
    where
        T: Debug,
        F: FnOnce(&mut RedactionWriter<'_, 'policy>) -> T,
    {
        if !self.admit_item() {
            self.write_field_truncated();
            return self;
        }
        let rendered = format!("{:?}", render(self.writer));
        self.writer.output.push_str(&rendered);
        self.writer.output.push_str(", ");
        self.writer.mark_frame_overflow();
        self
    }

    /// Writes one pre-redacted tuple or list item without adding debug quotes.
    pub fn item_text<F>(&mut self, render: F) -> &mut Self
    where
        F: FnOnce(&mut RedactionWriter<'_, 'policy>) -> String,
    {
        if !self.admit_item() {
            self.write_field_truncated();
            return self;
        }
        let rendered = render(self.writer);
        if rendered.is_empty() {
            self.writer.output.push_str("<truncated>");
            self.writer.field_truncated = true;
        } else {
            self.writer.output.push_str(&rendered);
        }
        self.writer.output.push_str(", ");
        self.writer.mark_frame_overflow();
        self
    }

    /// Writes a nested bracketed sequence inside the current structure.
    pub fn list<F>(&mut self, configure: F) -> &mut Self
    where
        F: for<'nested> FnOnce(&mut RedactionFields<'nested, 'session, 'policy>),
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
        let rendered = format!("{:?}", RedactedResult::new(value, self.writer.session),);
        self.write_prefix(name);
        self.writer.output.push_str(&rendered);
        self.writer.output.push_str(", ");
        self.writer.mark_frame_overflow();
        self
    }

    /// Writes a text-keyed map through the current session.
    pub fn map<M, K, V>(&mut self, name: &str, value: &M) -> &mut Self
    where
        M: RedactMapValue<K, V> + ?Sized,
        K: ?Sized,
        V: ?Sized,
    {
        if !self.admit_field() {
            self.writer.output.push_str("...: <truncated>");
            return self;
        }
        let rendered = format!("{:?}", RedactedMapResult::new(value, self.writer.session),);
        self.write_prefix(name);
        self.writer.output.push_str(&rendered);
        self.writer.output.push_str(", ");
        self.writer.mark_frame_overflow();
        self
    }

    /// Returns whether the next field may be inspected.
    #[must_use]
    fn admit_field(&mut self) -> bool {
        if self.writer.field_truncated {
            return false;
        }
        self.writer.session.admit_domain_field() == DomainTraversalAdmission::Render
    }

    #[inline]
    fn admit_item(&mut self) -> bool {
        !self.writer.field_truncated
            && self.writer.session.admit_domain_collection_item() == DomainTraversalAdmission::Render
    }

    fn write_prefix(&mut self, name: &str) {
        if self.named {
            self.writer.output.push_str(name);
            self.writer.output.push_str(": ");
        }
    }

    fn write_field_truncated(&mut self) {
        if !self.writer.field_truncated {
            if self.named {
                self.writer.output.push_str("...: <truncated>");
            } else {
                self.writer.output.push_str("<truncated>");
            }
            self.writer.field_truncated = true;
            self.writer.mark_frame_overflow();
        }
    }
}

/// Returns the greatest UTF-8 boundary not greater than `limit`.
fn floor_char_boundary(value: &str, limit: usize) -> usize {
    let mut boundary = limit.min(value.len());
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    boundary
}
