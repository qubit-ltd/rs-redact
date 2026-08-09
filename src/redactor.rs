// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Stateless redaction operations backed by an immutable policy.

use std::borrow::Cow;

use crate::FieldClassification;
use crate::FieldRedaction;
use crate::PassThroughReason;
use crate::RedactMapValueMut;
use crate::RedactedKeyedValue;
use crate::RedactedText;
use crate::RedactionPolicy;
use crate::RedactionSession;
use crate::Sensitivity;
use crate::policy::OutputCharge;
use crate::policy::ResolvedField;

/// Applies one immutable policy to scalar values and string maps.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redactor {
    /// Field classification and masking configuration.
    policy: RedactionPolicy,
}

impl Redactor {
    /// Creates a redactor using `policy`.
    ///
    /// # Parameters
    ///
    /// * `policy` - Immutable field classification and masking configuration.
    ///
    /// # Returns
    ///
    /// A redactor that owns the supplied policy snapshot.
    #[inline(always)]
    pub const fn new(policy: RedactionPolicy) -> Self {
        Self { policy }
    }

    /// Creates a redactor with the strict policy for untrusted scalar data.
    ///
    /// Unknown fields are masked at [`Sensitivity::Secret`].
    #[inline]
    pub fn strict() -> Self {
        Self::new(RedactionPolicy::strict())
    }

    /// Returns the immutable policy used by this redactor.
    ///
    /// # Returns
    ///
    /// A borrowed view of the redactor's policy snapshot.
    #[must_use = "use the policy snapshot backing this redactor"]
    #[inline(always)]
    pub const fn policy(&self) -> &RedactionPolicy {
        &self.policy
    }

    /// Redacts one value according to its field name.
    ///
    /// Unknown and explicitly allowed fields retain a borrow of `value`.
    /// Sensitive fields return the value produced by the configured mask.
    /// This method classifies only `field`; it never scans `value` for secret
    /// syntax. Do not pass an arbitrary error message or complete diagnostic
    /// under a generic field name and expect embedded credentials to be found.
    /// Use structured fields, [`Self::redact_at`] for an opaque value whose
    /// sensitivity is already known, or a fixed safe public summary with the
    /// original error retained only as an error source.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime of the input and any borrowed redacted result.
    ///
    /// # Parameters
    ///
    /// * `field` - Raw field name to classify.
    /// * `value` - Field value to redact when classified as sensitive.
    ///
    /// # Returns
    ///
    /// A typed result that distinguishes masked values from pass-through
    /// values while borrowing safe input where possible.
    #[must_use = "use the returned redacted value"]
    #[inline]
    pub fn redact_field<'a>(&self, field: &str, value: &'a str) -> FieldRedaction<'a> {
        let session = RedactionSession::operation(&self.policy);
        self.redact_field_with_session(&session, field, value)
    }

    /// Redacts one field while consuming the supplied operation session.
    ///
    /// This is the composition entry point for diagnostics that contain more
    /// than one field-producing adapter. Input accounting happens before the
    /// value is inspected, and generated masks are charged to the same
    /// session.
    #[must_use = "use the returned redacted value"]
    pub fn redact_field_with_session<'a>(
        &self,
        session: &RedactionSession<'_>,
        field: &str,
        value: &'a str,
    ) -> FieldRedaction<'a> {
        if !session.consume_input(field.len().saturating_add(value.len())) {
            return self.fallback_field(session);
        }
        let resolved = self.policy.resolve_field(field);
        match resolved {
            ResolvedField::Sensitive { sensitivity } => {
                let max_bytes = session.remaining_output_bytes();
                let masked = self
                    .policy
                    .masking()
                    .mask_bounded(sensitivity, value, max_bytes);
                let mask_len = masked.len();
                let fallback = self.opaque_mask();
                match session.charge_output_or_fallback(mask_len, fallback.len()) {
                    OutputCharge::Complete => FieldRedaction::Masked {
                        value: RedactedText::new(masked),
                        sensitivity,
                    },
                    OutputCharge::Fallback => FieldRedaction::Masked {
                        value: RedactedText::new(Cow::Owned(fallback.to_owned())),
                        sensitivity: Sensitivity::Secret,
                    },
                    OutputCharge::Exhausted => FieldRedaction::Masked {
                        value: RedactedText::new(Cow::Owned(String::new())),
                        sensitivity: Sensitivity::Secret,
                    },
                }
            }
            ResolvedField::PassThrough => {
                let reason = match self.policy.classify_field(field) {
                    FieldClassification::Allowed { .. } => PassThroughReason::Allowed,
                    FieldClassification::Sensitive { .. } | FieldClassification::Unknown => {
                        PassThroughReason::Unknown
                    }
                };
                match session.charge_output_or_fallback(value.len(), self.opaque_mask().len()) {
                    OutputCharge::Complete => FieldRedaction::PassedThrough { value, reason },
                    OutputCharge::Fallback => FieldRedaction::Masked {
                        value: RedactedText::new(Cow::Owned(self.opaque_mask().to_owned())),
                        sensitivity: Sensitivity::Secret,
                    },
                    OutputCharge::Exhausted => FieldRedaction::Masked {
                        value: RedactedText::new(Cow::Owned(String::new())),
                        sensitivity: Sensitivity::Secret,
                    },
                }
            }
        }
    }

    /// Redacts one value at an explicit sensitivity level.
    ///
    /// This ignores field classification and allow rules. Use it at a boundary
    /// where the value is known to be sensitive regardless of its field name.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime of the input and any borrowed redacted result.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity required by the calling boundary.
    /// * `value` - Value to mask.
    ///
    /// # Returns
    ///
    /// Typed redacted text produced by the configured mask for `level`.
    #[must_use = "use the returned redacted value"]
    #[inline]
    pub fn redact_at<'a>(&self, level: Sensitivity, value: &'a str) -> RedactedText<'a> {
        let session = RedactionSession::operation(&self.policy);
        self.redact_at_with_session(&session, level, value)
    }

    /// Redacts an explicitly sensitive value through an existing session.
    #[must_use = "use the returned redacted value"]
    pub fn redact_at_with_session<'a>(
        &self,
        session: &RedactionSession<'_>,
        level: Sensitivity,
        value: &'a str,
    ) -> RedactedText<'a> {
        if !session.consume_input(value.len()) {
            return self.fallback_text(session);
        }
        let masked =
            self.policy
                .masking()
                .mask_bounded(level, value, session.remaining_output_bytes());
        let length = masked.len();
        let fallback = self.opaque_mask();
        match session.charge_output_or_fallback(length, fallback.len()) {
            OutputCharge::Complete => RedactedText::new(masked),
            OutputCharge::Fallback => RedactedText::new(Cow::Owned(fallback.to_owned())),
            OutputCharge::Exhausted => RedactedText::new(Cow::Owned(String::new())),
        }
    }

    /// Returns the policy's opaque Secret mask.
    #[inline(always)]
    fn opaque_mask(&self) -> &str {
        self.policy.masking().mask_opaque(Sensitivity::Secret)
    }

    /// Charges one fail-closed scalar fallback through the shared session.
    fn fallback_text<'a>(&self, session: &RedactionSession<'_>) -> RedactedText<'a> {
        let fallback = self.opaque_mask();
        match session.charge_output_or_fallback(fallback.len(), fallback.len()) {
            OutputCharge::Complete => RedactedText::new(Cow::Owned(fallback.to_owned())),
            OutputCharge::Fallback | OutputCharge::Exhausted => {
                RedactedText::new(Cow::Owned(String::new()))
            }
        }
    }

    /// Wraps a charged fail-closed scalar fallback as a field result.
    fn fallback_field<'a>(&self, session: &RedactionSession<'_>) -> FieldRedaction<'a> {
        FieldRedaction::Masked {
            value: self.fallback_text(session),
            sensitivity: Sensitivity::Secret,
        }
    }

    /// Creates a lazy redacted view selected by an external key.
    ///
    /// The returned view borrows this redactor's policy snapshot. When its key
    /// is sensitive, it masks the complete value through
    /// [`RedactValue`](crate::RedactValue). Otherwise it delegates to the
    /// value's recursive redaction contracts.
    ///
    /// # Type Parameters
    ///
    /// * `'value` - Lifetime of the borrowed key and value.
    /// * `T` - Value type rendered or serialized through redaction.
    ///
    /// # Parameters
    ///
    /// * `key` - Field name used only for policy classification.
    /// * `value` - Value to render or serialize through the selected policy.
    ///
    /// # Returns
    ///
    /// A lazy keyed redaction view borrowing `key` and `value`.
    #[must_use = "format or serialize the returned keyed redaction view"]
    #[inline(always)]
    pub fn redact_keyed<'value, T: ?Sized>(
        &self,
        key: &'value str,
        value: &'value T,
    ) -> RedactedKeyedValue<'value, '_, T> {
        RedactedKeyedValue::new(key, value, &self.policy)
    }

    /// Creates a redacted copy of a text-keyed, mutable text-valued map.
    ///
    /// The source map is never modified. Its concrete collection type is
    /// preserved by cloning the collection before applying in-place redaction.
    ///
    /// # Type Parameters
    ///
    /// * `M` - Cloneable map-like collection returned after redaction.
    /// * `K` - Runtime key type used for field classification.
    /// * `V` - Mutable map-value type redacted in the cloned collection.
    ///
    /// # Parameters
    ///
    /// * `map` - Map whose values are classified by their corresponding keys.
    ///
    /// # Returns
    ///
    /// A map of the same type containing redacted values.
    #[must_use = "use the returned redacted map"]
    pub fn redact_map<M, K: ?Sized, V: ?Sized>(&self, map: &M) -> M
    where
        M: Clone + RedactMapValueMut<K, V>,
    {
        let mut redacted = map.clone();
        RedactMapValueMut::redact_map_in_place(&mut redacted, &self.policy);
        redacted
    }

    /// Redacts sensitive values of a text-keyed map in place.
    ///
    /// # Type Parameters
    ///
    /// * `M` - Mutable map-like collection type.
    /// * `K` - Runtime key type used for field classification.
    /// * `V` - Mutable map-value type redacted in place.
    ///
    /// # Parameters
    ///
    /// * `map` - Mutable map whose values are classified by their keys.
    #[inline(always)]
    pub fn redact_map_in_place<M, K: ?Sized, V: ?Sized>(&self, map: &mut M)
    where
        M: RedactMapValueMut<K, V> + ?Sized,
    {
        RedactMapValueMut::redact_map_in_place(map, &self.policy);
    }
}

impl Default for Redactor {
    /// Creates a redactor from the current global redaction configuration.
    ///
    /// # Returns
    ///
    /// A redactor that is unaffected by later policy configuration attempts.
    #[inline(always)]
    fn default() -> Self {
        Self::new(RedactionPolicy::default())
    }
}
