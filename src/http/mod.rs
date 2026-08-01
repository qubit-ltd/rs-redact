// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable HTTP redaction policy, bounded body input, and safe results.

mod body_budget;
mod body_budget_error;
mod body_capture;
mod body_capture_error;
mod body_redaction;
mod body_redaction_reason;
mod body_redaction_status;
mod http_redaction_policy;
mod http_redaction_policy_builder;
mod http_redactor;
mod internal;
mod redacted_headers;
mod text_body_policy;
mod unkeyed_json_value_policy;
mod url_path_policy;

pub use crate::{DiagnosticBudget, DiagnosticBudgetError, JsonDepthBudget, JsonDepthBudgetError};
pub use body_budget::BodyBudget;
pub use body_budget_error::BodyBudgetError;
pub use body_capture::BodyCapture;
pub use body_capture_error::BodyCaptureError;
pub use body_redaction::BodyRedaction;
pub use body_redaction_reason::BodyRedactionReason;
pub use body_redaction_status::BodyRedactionStatus;
pub use http_redaction_policy::HttpRedactionPolicy;
pub use http_redaction_policy_builder::HttpRedactionPolicyBuilder;
pub use http_redactor::HttpRedactor;
pub use redacted_headers::RedactedHeaders;
pub use text_body_policy::TextBodyPolicy;
pub use unkeyed_json_value_policy::UnkeyedJsonValuePolicy;
pub use url_path_policy::UrlPathPolicy;

use std::borrow::Cow;

use crate::{RedactedText, RedactionRules, Sensitivity};

/// Borrowed field-rule executor used within one HTTP redaction call.
///
/// It deliberately owns no policy snapshot: [`HttpRedactor`] is the sole HTTP
/// policy owner and supplies the context rules for the duration of an
/// operation.
pub(in crate::http) struct FieldRedactor<'a> {
    rules: &'a RedactionRules,
}

impl<'a> FieldRedactor<'a> {
    /// Borrows a field-rule snapshot.
    pub(in crate::http) const fn new(rules: &'a RedactionRules) -> Self {
        Self { rules }
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
        let resolved = self.rules.resolve_field(field);
        match (resolved.sensitivity, resolved.masking) {
            (Some(level), Some(masking)) => Some(RedactedText::new(
                masking.mask_bounded(level, value, max_bytes),
            )),
            (None, None) => None,
            _ => unreachable!("a resolved sensitivity always has a mask"),
        }
    }

    /// Masks an explicitly sensitive native value with application masking.
    pub(in crate::http) fn mask_bounded<'value>(
        &self,
        level: Sensitivity,
        value: &'value str,
        max_bytes: usize,
    ) -> Cow<'value, str> {
        self.rules.masking().mask_bounded(level, value, max_bytes)
    }

    /// Returns the borrowed immutable rules snapshot.
    pub(in crate::http) const fn rules(&self) -> &'a RedactionRules {
        self.rules
    }
}
