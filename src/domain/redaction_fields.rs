// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Field scope for structured domain redaction.

use std::fmt::Debug;

use crate::Sensitivity;
use crate::domain::Redact;
use crate::domain::RedactLevelValue;
use crate::domain::RedactionWriter;
use crate::domain::internal::bounded_capture::bounded_debug;
use crate::domain::internal::resolve_keyed_field;
use crate::policy::ResolvedField;

/// Provides bounded redaction operations for named domain fields.
pub struct RedactionFields<'writer, 'session> {
    /// Domain writer receiving field output.
    pub(super) writer: &'writer mut RedactionWriter<'session>,
    /// Whether field names are emitted before values.
    pub(super) named: bool,
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
    /// [`Sensitivity::Secret`], `access` is not evaluated while redaction is
    /// enabled.
    ///
    /// `access` must nevertheless be a valid lazy accessor for the actual
    /// field value. In particular, callers must not replace it with a panic or
    /// an unrelated sentinel merely because `level` is
    /// [`Sensitivity::Secret`]: a disabled policy restores source values and
    /// therefore evaluates the closure. Lower effective sensitivity levels
    /// may also require the raw value to produce a partial mask.
    ///
    /// # Parameters
    ///
    /// * `level` - Minimum sensitivity enforced for the field.
    /// * `name` - Diagnostic field name used for policy classification.
    /// * `access` - Lazy accessor that returns the actual field value whenever
    ///   the selected policy needs it.
    ///
    /// # Returns
    ///
    /// This field writer for continued chained output.
    ///
    /// # Panics
    ///
    /// Propagates a panic from `access` when the selected policy evaluates the
    /// closure, including when redaction is disabled.
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
            let (value, mask_truncated) = self
                .writer
                .session
                .policy()
                .masking()
                .mask_bounded_with_truncation(
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
                if let ResolvedField::Sensitive { sensitivity } =
                    self.writer.session.policy().resolve_field(key)
                {
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

    /// Writes map keys at a fixed level and leaves values unmarked.
    pub(crate) fn map_key_level_entries<'value, I, K, V>(
        &mut self,
        name: &str,
        entries: I,
        key_level: Sensitivity,
        value_level: Option<Sensitivity>,
    ) -> &mut Self
    where
        I: IntoIterator<Item = (&'value K, &'value V)>,
        K: super::RedactLevelValue + 'value,
        V: super::RedactLevelValue + 'value,
    {
        if !self.admit_field() {
            self.write_field_truncated();
            return self;
        }
        self.write_prefix(name);
        self.writer.map(|output| {
            for (key, value) in entries {
                output.key_level_entry(key, value, key_level, value_level);
            }
        });
        self.writer.write_fragment(", ");
        self
    }

    /// Writes a supported map with an explicit key sensitivity.
    #[doc(hidden)]
    pub fn map_level_values<T>(
        &mut self,
        name: &str,
        value: &T,
        key_level: Sensitivity,
        value_level: Option<Sensitivity>,
    ) -> &mut Self
    where
        T: super::RedactMapKeyValue + ?Sized,
    {
        value.write_redacted_map_levels(self, name, key_level, value_level);
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

    /// Writes a value whose sensitivity is selected by a sibling policy key.
    ///
    /// The output field name remains `name`, while `key` is the runtime text
    /// used for policy lookup. This matches map-entry classification semantics:
    /// pass-through keys preserve the value, and sensitive keys redact it at
    /// the policy-selected level.
    #[doc(hidden)]
    pub fn keyed_value<K, T>(&mut self, name: &str, key: &K, value: &T) -> &mut Self
    where
        K: AsRef<str> + ?Sized,
        T: RedactLevelValue + ?Sized,
    {
        if !self.admit_field() {
            self.write_field_truncated();
            return self;
        }
        let policy = self.writer.session.policy();
        let disabled = policy.is_disabled();
        let resolved = (!disabled).then(|| resolve_keyed_field(policy, key.as_ref()));
        if self.writer.session.is_inspection() {
            if let Some(ResolvedField::Sensitive { sensitivity }) = resolved {
                self.writer.session.observe_sensitivity(sensitivity);
            }
            return self;
        }
        self.write_prefix(name);
        if !self.writer.can_write() {
            return self;
        }
        match resolved {
            Some(ResolvedField::Sensitive { sensitivity }) => {
                value.write_redacted_level(self.writer, sensitivity);
            }
            Some(ResolvedField::PassThrough) | None => self.writer.write_debug(&value),
        }
        self.writer.write_fragment(", ");
        self
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

    /// Admits one tuple item against the active collection limit.
    #[inline]
    fn admit_item(&mut self) -> bool {
        !self.writer.session.domain_frame_is_truncated()
            && self.writer.session.admit_domain_collection_item()
    }

    /// Writes the field-name prefix for named structures.
    fn write_prefix(&mut self, name: &str) {
        if self.named {
            self.writer.write_fragment(name);
            self.writer.write_fragment(": ");
        }
    }

    /// Publishes the structural truncation marker once.
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
