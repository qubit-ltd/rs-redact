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
use crate::RedactedText;
use crate::RedactionRules;
use crate::Sensitivity;
use crate::policy::ResolvedField;

/// Borrowed field-rule executor used within one HTTP redaction call.
///
/// It deliberately owns no policy snapshot: [`super::HttpRedactor`] is the
/// sole HTTP policy owner and supplies context rules for each operation.
pub(in crate::http) struct FieldRedactor<'a> {
    base_rules: &'a RedactionRules,
    context_rules: &'a RedactionRules,
    masking: &'a MaskingPolicy,
}

impl<'a> FieldRedactor<'a> {
    /// Borrows `rules` for one HTTP redaction operation.
    pub(in crate::http) const fn new(
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

    /// Masks a classified value without allocating beyond `max_bytes`.
    pub(in crate::http) fn redact_bounded<'value>(
        &self,
        field: &str,
        value: &'value str,
        max_bytes: usize,
    ) -> RedactedText<'value> {
        self.redact_bounded_if_sensitive(field, value, max_bytes)
            .unwrap_or_else(|| RedactedText::new(Cow::Borrowed(value)))
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
    pub(in crate::http) fn redact_bounded_if_sensitive<'value>(
        &self,
        field: &str,
        value: &'value str,
        max_bytes: usize,
    ) -> Option<RedactedText<'value>> {
        let resolved = stronger(
            self.base_rules.resolve_field(field),
            self.context_rules.resolve_field(field),
        );
        match resolved {
            ResolvedField::Sensitive { sensitivity } => Some(RedactedText::new(
                self.masking.mask_bounded(sensitivity, value, max_bytes),
            )),
            ResolvedField::PassThrough => None,
        }
    }

    /// Masks an explicitly sensitive native value with the shared mask table.
    pub(in crate::http) fn mask_bounded<'value>(
        &self,
        level: Sensitivity,
        value: &'value str,
        max_bytes: usize,
    ) -> Cow<'value, str> {
        self.masking.mask_bounded(level, value, max_bytes)
    }

    /// Returns the borrowed immutable rule snapshot.
    pub(in crate::http) const fn base_rules(&self) -> &'a RedactionRules {
        self.base_rules
    }

    /// Returns the context-specific rule overrides for the current operation.
    pub(in crate::http) const fn context_rules(&self) -> &'a RedactionRules {
        self.context_rules
    }

    /// Returns the shared mask table for the current HTTP operation.
    pub(in crate::http) const fn masking(&self) -> &'a MaskingPolicy {
        self.masking
    }
}

/// Combines a base decision with a context enhancement without permitting the
/// context to lower the base protection level.
fn stronger(base: ResolvedField, context: ResolvedField) -> ResolvedField {
    match (base, context) {
        (
            ResolvedField::Sensitive { sensitivity: base },
            ResolvedField::Sensitive {
                sensitivity: context,
            },
        ) => ResolvedField::Sensitive {
            sensitivity: base.max(context),
        },
        (ResolvedField::Sensitive { sensitivity }, ResolvedField::PassThrough)
        | (ResolvedField::PassThrough, ResolvedField::Sensitive { sensitivity }) => {
            ResolvedField::Sensitive { sensitivity }
        }
        (ResolvedField::PassThrough, ResolvedField::PassThrough) => ResolvedField::PassThrough,
    }
}
