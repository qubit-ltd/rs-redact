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
        !self.writer.session.domain_frame_is_truncated() && self.writer.session.admit_domain_collection_item()
    }

    /// Publishes the sequence truncation marker once.
    fn write_truncated(&mut self) {
        if !self.writer.session.domain_frame_is_truncated() {
            self.writer.write_fragment("<truncated>");
            self.writer.truncate_without_output_limit();
        }
    }
}
