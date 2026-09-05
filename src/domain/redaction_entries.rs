// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Map-entry scope for structured domain redaction.

use std::fmt::Debug;

use crate::Sensitivity;
use crate::domain::Redact;
use crate::domain::RedactionWriter;

/// Provides bounded redaction operations for map-like domain values.
pub struct RedactionEntries<'writer, 'session> {
    /// Domain writer receiving map entries.
    pub(super) writer: &'writer mut RedactionWriter<'session>,
    /// Admission reserved by the iterator driver for its next entry operation.
    pub(super) admitted_entry: bool,
}

impl<'writer, 'session> RedactionEntries<'writer, 'session> {
    /// Drives `values`, reserving each entry before invoking `write`.
    ///
    /// Capacity is checked before advancing the iterator. The first entry
    /// operation in `write` consumes the reservation; additional operations are
    /// charged separately. Empty callbacks still consume an entry.
    /// Unknown-length iterators conservatively truncate when checking their
    /// end would exceed the budget. Iterator and callback panics propagate
    /// to the transaction.
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
            if !self.admit_entry() {
                self.write_truncated();
                break;
            }
            self.admitted_entry = true;
            write(self, value);
            self.admitted_entry = false;
        }
        self
    }

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
        if self.writer.can_write() {
            self.writer.write_debug(&access());
        }
        self.writer.write_fragment(", ");
        self
    }

    /// Writes one explicitly sensitive map entry.
    pub fn sensitive_entry<T, F>(&mut self, level: Sensitivity, name: &str, access: F) -> &mut Self
    where
        T: Debug,
        F: FnOnce() -> T,
    {
        if self.writer.session.policy().is_disabled() {
            return self.unredacted_entry(name, access);
        }
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
            self.writer.write_masked_debug(effective_level, &access());
        }
        self.writer.write_fragment(", ");
        self
    }

    /// Writes a map value with an explicit sensitivity while preserving its
    /// recursive level-capable shape.
    pub(crate) fn level_value_entry<K, T>(&mut self, key: &K, value: &T, level: Sensitivity) -> &mut Self
    where
        K: Debug + ?Sized,
        T: super::RedactLevelValue + ?Sized,
    {
        if !self.admit_entry() {
            self.write_truncated();
            return self;
        }
        self.writer.write_debug(key);
        self.writer.write_fragment(": ");
        if self.writer.can_write() {
            value.write_redacted_level(self.writer, level);
        }
        self.writer.write_fragment(", ");
        self
    }

    /// Writes a level-redacted key and an optionally level-redacted value.
    pub(crate) fn key_level_entry<K, V>(
        &mut self,
        key: &K,
        value: &V,
        key_level: Sensitivity,
        value_level: Option<Sensitivity>,
    ) -> &mut Self
    where
        K: super::RedactLevelValue + ?Sized,
        V: super::RedactLevelValue + ?Sized,
    {
        if !self.admit_entry() {
            self.write_truncated();
            return self;
        }
        key.write_redacted_level(self.writer, key_level);
        self.writer.write_fragment(": ");
        if !self.writer.can_write() {
            return self;
        }
        if let Some(level) = value_level {
            value.write_redacted_level(self.writer, level);
        } else {
            self.writer.write_debug(value);
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

    /// Admits one entry against the active collection limit.
    fn admit_entry(&mut self) -> bool {
        if !self.writer.can_write() {
            return false;
        }
        std::mem::take(&mut self.admitted_entry) || self.writer.session.admit_domain_collection_item()
    }

    /// Writes a map key and separator.
    fn write_prefix(&mut self, name: &str) {
        self.writer.write_fragment(name);
        self.writer.write_fragment(": ");
    }

    /// Publishes the map truncation marker once.
    fn write_truncated(&mut self) {
        if !self.writer.session.domain_frame_is_truncated() {
            self.writer.write_fragment("...: <truncated>");
            self.writer.truncate_without_output_limit();
        }
    }
}
