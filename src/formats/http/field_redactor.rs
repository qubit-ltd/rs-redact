// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed field-rule execution for one HTTP redaction operation.

use std::borrow::Cow;

use crate::MaskingPolicy;
use crate::RedactionRules;
use crate::Sensitivity;
use crate::output::MaskedValue;
use crate::policy::ResolvedField;

/// Borrowed field-rule executor used within one HTTP redaction call.
///
/// It deliberately owns no policy snapshot: the parent runtime supplies
/// context rules for each operation.
pub(in crate::formats::http) struct FieldRedactor<'a> {
    /// Application-wide field rules evaluated for every HTTP context.
    base_rules: &'a RedactionRules,
    /// Context-specific rules evaluated alongside the base rules.
    context_rules: &'a RedactionRules,
    /// Mask generator used after the strongest rule is resolved.
    masking: &'a MaskingPolicy,
}

impl<'a> FieldRedactor<'a> {
    /// Borrows the application rules, context rules, and mask policy.
    ///
    /// # Parameters
    ///
    /// - `base_rules`: Application rules shared by every HTTP context.
    /// - `context_rules`: Additional rules for this field namespace.
    /// - `masking`: Mask table applied to the strongest resolved sensitivity.
    ///
    /// # Returns
    ///
    /// An executor borrowing all three immutable policy components.
    #[must_use]
    #[inline(always)]
    pub(in crate::formats::http) const fn new(
        base_rules: &'a RedactionRules,
        context_rules: &'a RedactionRules,
        masking: &'a MaskingPolicy,
    ) -> Self {
        Self {
            base_rules,
            context_rules,
            masking,
        }
    }

    /// Returns the borrowed immutable rule snapshot.
    ///
    /// # Returns
    ///
    /// The application rules borrowed at construction.
    #[must_use]
    #[inline(always)]
    pub(in crate::formats::http) const fn base_rules(&self) -> &'a RedactionRules {
        self.base_rules
    }

    /// Returns the context-specific rule overrides for the current operation.
    ///
    /// # Returns
    ///
    /// The context rules borrowed at construction.
    #[must_use]
    #[inline(always)]
    pub(in crate::formats::http) const fn context_rules(&self) -> &'a RedactionRules {
        self.context_rules
    }

    /// Returns the shared mask table for the current HTTP operation.
    ///
    /// # Returns
    ///
    /// The immutable shared mask table borrowed at construction.
    #[must_use]
    #[inline(always)]
    pub(in crate::formats::http) const fn masking(&self) -> &'a MaskingPolicy {
        self.masking
    }

    /// Reports whether the final atomic rule resolution protects `field`.
    ///
    /// # Parameters
    ///
    /// - `field`: Raw field name resolved against both rule sets.
    ///
    /// # Returns
    ///
    /// Whether either rule set requires masking after atomic rule resolution.
    #[must_use]
    #[inline]
    pub(in crate::formats::http) fn is_sensitive(&self, field: &str) -> bool {
        matches!(
            self.base_rules
                .resolve_field(field)
                .stronger(self.context_rules.resolve_field(field)),
            ResolvedField::Sensitive { .. }
        )
    }

    /// Returns the final sensitivity selected for one field.
    ///
    /// # Parameters
    ///
    /// - `field`: Raw field name resolved against both rule sets.
    ///
    /// # Returns
    ///
    /// `Some(level)` for the strongest sensitive classification; `None` when
    /// the combined rules permit pass-through.
    #[must_use]
    #[inline]
    pub(in crate::formats::http) fn sensitivity(&self, field: &str) -> Option<Sensitivity> {
        match self
            .base_rules
            .resolve_field(field)
            .stronger(self.context_rules.resolve_field(field))
        {
            ResolvedField::Sensitive { sensitivity } => Some(sensitivity),
            ResolvedField::PassThrough => None,
        }
    }

    /// Masks a classified value without allocating beyond `max_bytes`.
    ///
    /// # Parameters
    ///
    /// - `field`: Raw field name resolved against both rule sets.
    /// - `value`: Source text borrowed when the rules permit pass-through.
    /// - `max_bytes`: Maximum allocation for generated masking text.
    ///
    /// # Returns
    ///
    /// The bounded mask for sensitive fields, or the unchanged borrowed value.
    /// The caller must apply its output limit to pass-through text.
    #[must_use]
    #[inline]
    pub(in crate::formats::http) fn redact_bounded<'value>(
        &self,
        field: &str,
        value: &'value str,
        max_bytes: usize,
    ) -> MaskedValue<'value> {
        self.redact_bounded_if_sensitive(field, value, max_bytes)
            .unwrap_or_else(|| MaskedValue::new(Cow::Borrowed(value)))
    }

    /// Redacts a field only when its atomic rule resolution is sensitive.
    ///
    /// # Parameters
    ///
    /// * `field` - Raw field name to resolve once against application and floor
    ///   rules.
    /// * `value` - UTF-8 value to mask when the field is sensitive.
    /// * `max_bytes` - Maximum bytes allocated for a generated mask.
    ///
    /// # Returns
    ///
    /// `Some` containing the final-mask result when the field is sensitive, or
    /// `None` when callers should continue their non-sensitive handling.
    #[must_use]
    #[inline]
    pub(in crate::formats::http) fn redact_bounded_if_sensitive<'value>(
        &self,
        field: &str,
        value: &'value str,
        max_bytes: usize,
    ) -> Option<MaskedValue<'value>> {
        let resolved = self
            .base_rules
            .resolve_field(field)
            .stronger(self.context_rules.resolve_field(field));
        match resolved {
            ResolvedField::Sensitive { sensitivity } => Some(MaskedValue::new(self.masking.mask_bounded(
                sensitivity,
                value,
                max_bytes,
            ))),
            ResolvedField::PassThrough => None,
        }
    }

    /// Masks an explicitly sensitive native value with the shared mask table.
    ///
    /// # Parameters
    ///
    /// - `level`: Explicit sensitivity supplied by the native HTTP
    ///   representation.
    /// - `value`: Source text used only by masks that preserve part of the
    ///   value.
    /// - `max_bytes`: Maximum allocation for generated masking text.
    ///
    /// # Returns
    ///
    /// The mask selected by the shared table, possibly borrowing its input.
    #[must_use]
    #[inline(always)]
    pub(in crate::formats::http) fn mask_bounded<'value>(
        &self,
        level: Sensitivity,
        value: &'value str,
        max_bytes: usize,
    ) -> Cow<'value, str> {
        self.masking.mask_bounded(level, value, max_bytes)
    }
}
