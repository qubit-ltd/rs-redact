// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Sequence-item scope for structured domain redaction.

use std::fmt::Debug;

use crate::Sensitivity;
use crate::domain::Redact;
use crate::domain::RedactLevelValue;
use crate::domain::RedactionWriter;

/// Provides bounded redaction operations for sequence-like domain values.
pub struct RedactionItems<'writer, 'session> {
    /// Domain writer receiving sequence items.
    pub(super) writer: &'writer mut RedactionWriter<'session>,
    /// Admission reserved by the iterator driver for its next item operation.
    pub(super) admitted_item: bool,
}

impl<'writer, 'session> RedactionItems<'writer, 'session> {
    /// Drives `values` while the shared budget admits each next item.
    ///
    /// Checks capacity before advancing the iterator and reserves one
    /// collection item for `write`. The callback's first item operation
    /// consumes that reservation; any additional operations use additional
    /// budget. Empty callbacks still consume their reservation. An iterator
    /// of unknown length conservatively truncates when no capacity remains
    /// to check its end. Panics from the iterator or callback propagate to
    /// the owning transaction.
    pub fn for_each<I, F>(&mut self, values: I, mut write: F) -> &mut Self
    where
        I: IntoIterator,
        F: FnMut(&mut Self, I::Item),
    {
        let mut values = values.into_iter();
        while values.size_hint().1 != Some(0) {
            if !self.writer.can_write() || !self.writer.session.preflight_collection_item() {
                self.write_truncated();
                break;
            }
            let Some(value) = values.next() else { break };
            if !self.admit_item() {
                self.write_truncated();
                break;
            }
            self.admitted_item = true;
            write(self, value);
            self.admitted_item = false;
        }
        self
    }

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
        if self.writer.session.policy().is_disabled() {
            return self.unredacted_item(access);
        }
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

    /// Writes one borrowed parsed JSON value as a sequence item.
    ///
    /// The value is traversed through the active JSON policy and shared
    /// structural, input, and output budgets without cloning or first
    /// serializing it into an intermediate string.
    #[cfg(feature = "json")]
    pub fn json_value_item(&mut self, value: &serde_json::Value) -> &mut Self {
        if !self.admit_item() {
            self.write_truncated();
            return self;
        }
        self.writer.write_json_value(value);
        self.writer.write_fragment(", ");
        self
    }

    /// Writes one item with an explicitly supplied sensitivity.
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

    /// Admits one item against the active collection limit.
    fn admit_item(&mut self) -> bool {
        if !self.writer.can_write() {
            return false;
        }
        std::mem::take(&mut self.admitted_item) || self.writer.session.admit_domain_collection_item()
    }

    /// Publishes the sequence truncation marker once.
    fn write_truncated(&mut self) {
        if !self.writer.session.domain_frame_is_truncated() {
            self.writer.write_fragment("<truncated>");
            self.writer.truncate_without_output_limit();
        }
    }
}
