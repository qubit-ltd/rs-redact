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

pub struct RedactionEntries<'writer, 'session> {
    /// Domain writer receiving map entries.
    pub(super) writer: &'writer mut RedactionWriter<'session>,
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

    /// Admits one entry against the active collection limit.
    fn admit_entry(&mut self) -> bool {
        !self.writer.session.domain_frame_is_truncated() && self.writer.session.admit_domain_collection_item()
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
