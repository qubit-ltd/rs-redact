// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Stateless redaction operations backed by an immutable policy.

use std::borrow::Cow;
use std::sync::PoisonError;

use crate::FieldClassification;
use crate::FieldRedaction;
use crate::PassThroughReason;
use crate::RedactionCompletion;
use crate::RedactionPolicy;
use crate::RedactionSession;
use crate::Sensitivity;
use crate::config::RedactionConfig;
use crate::domain::Redact;
use crate::domain::RedactMapValueMut;
use crate::domain::RedactedKeyedValue;
use crate::formats::argv::ArgvRedactor;
use crate::formats::env::EnvRedactor;
#[cfg(feature = "http")]
use crate::formats::http::HttpRedactor;
#[cfg(feature = "uri")]
use crate::formats::uri::UriRedactor;
use crate::output::MaskedValue;
use crate::output::redaction_output::RedactionOutput;
use crate::policy::DiagnosticBudget;
use crate::policy::FragmentCompletion;
use crate::policy::RedactionAdmission;
use crate::policy::ResolvedField;

/// Applies one immutable policy to scalar values and string maps.
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
    #[must_use]
    #[inline(always)]
    pub fn new<C>(config: C) -> Self
    where
        C: Into<RedactionConfig>,
    {
        Self {
            policy: config.into().into_policy(),
        }
    }

    /// Creates a redactor from the immutable built-in standard policy.
    #[must_use]
    #[inline]
    pub fn standard() -> Self {
        Self::new(RedactionPolicy::standard())
    }

    /// Returns a snapshot of the current application default redactor.
    ///
    /// The returned value is detached from the global slot. Later calls to
    /// [`Self::set_default`] do not alter this redactor or sessions created
    /// from it.
    #[must_use]
    pub fn current_default() -> Self {
        match crate::facade::default_redactor::slot().read() {
            Ok(redactor) => redactor.clone(),
            Err(error) => PoisonError::into_inner(error).clone(),
        }
    }

    /// Atomically replaces the application default redactor.
    ///
    /// The replacement is linearizable: concurrent readers observe either the
    /// complete previous snapshot or the complete new snapshot. Existing
    /// redactors and sessions keep their own snapshots. The previous default
    /// is returned so callers can restore it after a scoped change.
    #[must_use]
    pub fn set_default(redactor: Self) -> Self {
        let mut current = match crate::facade::default_redactor::slot().write() {
            Ok(guard) => guard,
            Err(error) => PoisonError::into_inner(error),
        };
        std::mem::replace(&mut *current, redactor)
    }

    /// Redacts one domain value into final text and an execution summary.
    #[must_use]
    pub fn redact<T>(&self, value: &T) -> crate::RedactionOutput
    where
        T: Redact + ?Sized,
    {
        let mut session = self.session();
        let mut writer = crate::domain::RedactionWriter::new_root(&mut session);
        value.write_redacted(&mut writer);
        let rendered = writer.finish();
        session.append_committed_output(&rendered);
        session.finish()
    }

    /// Creates a redactor with the strict policy for untrusted scalar data.
    ///
    /// Unknown fields are masked at [`Sensitivity::Secret`].
    #[must_use]
    #[inline]
    pub fn strict() -> Self {
        Self::new(RedactionConfig::strict())
    }

    /// Returns the immutable policy used by this redactor.
    ///
    /// # Returns
    ///
    /// A borrowed view of the redactor's policy snapshot.
    #[must_use]
    #[inline(always)]
    pub const fn policy(&self) -> &RedactionPolicy {
        &self.policy
    }

    /// Creates mutable accounting for one diagnostic event.
    ///
    /// # Returns
    ///
    /// A session borrowing this redactor's immutable policy.
    #[must_use]
    #[inline]
    pub fn session(&self) -> RedactionSession<'_> {
        RedactionSession::new(&self.policy)
    }

    /// Creates an argument-vector adapter using this policy snapshot.
    #[must_use]
    #[inline]
    pub fn argv(&self) -> ArgvRedactor {
        ArgvRedactor::new(self.clone())
    }

    /// Creates an environment adapter using this policy snapshot.
    #[must_use]
    #[inline]
    pub fn env(&self) -> EnvRedactor {
        EnvRedactor::new(self.clone())
    }

    /// Creates an HTTP adapter using this policy snapshot.
    #[cfg(feature = "http")]
    #[must_use]
    #[inline]
    pub fn http(&self) -> HttpRedactor {
        HttpRedactor::new(self.policy.clone())
    }

    /// Creates a URI adapter using this policy snapshot.
    #[cfg(feature = "uri")]
    #[must_use]
    #[inline]
    pub fn uri(&self) -> UriRedactor {
        UriRedactor::new(self.policy.clone())
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
    #[must_use]
    #[inline]
    pub fn redact_field<'a>(&self, field: &str, value: &'a str) -> FieldRedaction<'a> {
        let mut budget = DiagnosticBudget::new(self.policy.limits().ordinary_operation());
        redact_field_with_budget(&self.policy, &mut budget, field, value)
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
    #[must_use]
    #[inline]
    pub fn redact_at<'a>(&self, level: Sensitivity, value: &'a str) -> MaskedValue<'a> {
        let mut budget = DiagnosticBudget::new(self.policy.limits().ordinary_operation());
        redact_at_with_budget(&self.policy, &mut budget, level, value)
    }

    /// Creates a lazy redacted view selected by an external key.
    ///
    /// The returned view borrows this redactor's policy snapshot. When its key
    /// is sensitive, it masks the complete value through
    /// [`RedactValue`](crate::domain::RedactValue). Otherwise it delegates to
    /// the value's recursive redaction contracts.
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
    #[must_use]
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
    #[must_use]
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

impl RedactionSession<'_> {
    /// Redacts one field through this diagnostic event's shared budget.
    ///
    /// # Parameters
    ///
    /// * `field` - Raw field name to classify.
    /// * `value` - Field value to redact when classified as sensitive.
    ///
    /// # Returns
    ///
    /// A charged field result that borrows safe input where possible.
    #[must_use]
    pub fn redact_field<'value>(&mut self, field: &str, value: &'value str) -> FieldRedaction<'value> {
        let (redacted, _) = self.redact_field_with_completion(field, value);
        redacted
    }

    /// Redacts one field into owned safe text with its fragment completion.
    ///
    /// # Parameters
    ///
    /// * `field` - Raw field name to classify.
    /// * `value` - Field value to redact when classified as sensitive.
    ///
    /// # Returns
    ///
    /// Owned log-safe output whose completion distinguishes a full result, a
    /// non-empty fallback, and an empty exhausted result.
    pub(crate) fn redact_field_output(&mut self, field: &str, value: &str) -> RedactionOutput {
        let (redacted, completion) = self.redact_field_with_completion(field, value);
        redaction_output(redacted.escape_for_log(), completion)
    }

    /// Redacts one field and preserves its exact fragment completion.
    ///
    /// # Parameters
    ///
    /// * `field` - Raw field name to classify.
    /// * `value` - Field value to redact when classified as sensitive.
    ///
    /// # Returns
    ///
    /// The charged field result and whether it was complete, substituted, or
    /// unable to emit safe text.
    #[must_use]
    fn redact_field_with_completion<'value>(
        &mut self,
        field: &str,
        value: &'value str,
    ) -> (FieldRedaction<'value>, RedactionCompletion) {
        let policy = self.policy();
        let fallback = opaque_mask(policy);
        let fallback_bytes = log_safe_len(fallback);
        let input_bytes = field.len().saturating_add(value.len());
        let session_output_bytes = self.remaining_output_bytes();
        let domain_output_limit = crate::domain::internal::mask_byte_limit().unwrap_or(usize::MAX);
        let admission = self.admit(input_bytes, domain_output_limit, fallback_bytes);
        let RedactionAdmission::Render { max_output_bytes } = admission else {
            return (
                admission_field_fallback(admission, fallback),
                redaction_admission_completion(admission),
            );
        };
        let (redacted, mask_truncated) = redact_field_unbudgeted(policy, field, value, max_output_bytes);
        let output_bytes = log_safe_len(redacted.as_str());
        if output_bytes <= max_output_bytes {
            let completion = if mask_truncated {
                truncation_completion(domain_output_limit, session_output_bytes)
            } else {
                FragmentCompletion::Complete
            };
            self.commit_output(output_bytes, completion);
            let completion = redaction_fragment_completion(redacted.as_str(), completion);
            return (redacted, completion);
        }
        let completion = truncation_completion(domain_output_limit, session_output_bytes);
        let redacted = terminal_session_field_fallback(self, max_output_bytes, fallback, fallback_bytes, completion);
        let completion = redaction_fragment_completion(redacted.as_str(), completion);
        (redacted, completion)
    }

    /// Redacts one explicitly sensitive value through this diagnostic event.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity required by the calling boundary.
    /// * `value` - Value to mask.
    ///
    /// # Returns
    ///
    /// Charged redacted text produced by the configured mask.
    #[must_use]
    pub fn redact_at<'value>(&mut self, level: Sensitivity, value: &'value str) -> MaskedValue<'value> {
        let (redacted, _) = self.redact_at_with_completion(level, value);
        redacted
    }

    /// Redacts one sensitive value into owned safe text with its completion.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity required by the calling boundary.
    /// * `value` - Value to mask.
    ///
    /// # Returns
    ///
    /// Owned log-safe output whose completion distinguishes a full result, a
    /// non-empty fallback, and an empty exhausted result.
    pub(crate) fn redact_at_output(&mut self, level: Sensitivity, value: &str) -> RedactionOutput {
        let (redacted, completion) = self.redact_at_with_completion(level, value);
        redaction_output(redacted.escape_for_log(), completion)
    }

    /// Redacts one sensitive value and preserves its fragment completion.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity required by the calling boundary.
    /// * `value` - Value to mask.
    ///
    /// # Returns
    ///
    /// The charged value and whether it was complete, substituted, or unable
    /// to emit safe text.
    #[must_use]
    fn redact_at_with_completion<'value>(
        &mut self,
        level: Sensitivity,
        value: &'value str,
    ) -> (MaskedValue<'value>, RedactionCompletion) {
        let policy = self.policy();
        let fallback = opaque_mask(policy);
        let fallback_bytes = log_safe_len(fallback);
        let session_output_bytes = self.remaining_output_bytes();
        let domain_output_limit = crate::domain::internal::mask_byte_limit().unwrap_or(usize::MAX);
        let admission = self.admit(value.len(), domain_output_limit, fallback_bytes);
        let RedactionAdmission::Render { max_output_bytes } = admission else {
            return (
                admission_text_fallback(admission, fallback),
                redaction_admission_completion(admission),
            );
        };
        let (masked, mask_truncated) = policy
            .masking()
            .mask_bounded_with_truncation(level, value, max_output_bytes);
        let output_bytes = log_safe_len(masked.as_ref());
        if output_bytes <= max_output_bytes {
            let completion = if mask_truncated {
                truncation_completion(domain_output_limit, session_output_bytes)
            } else {
                FragmentCompletion::Complete
            };
            self.commit_output(output_bytes, completion);
            let redacted = MaskedValue::new(masked);
            let completion = redaction_fragment_completion(redacted.as_str(), completion);
            return (redacted, completion);
        }
        let completion = truncation_completion(domain_output_limit, session_output_bytes);
        let redacted = terminal_session_text_fallback(self, max_output_bytes, fallback, fallback_bytes, completion);
        let completion = redaction_fragment_completion(redacted.as_str(), completion);
        (redacted, completion)
    }
}

/// Converts log-safe fragment text and completion into the shared carrier.
///
/// # Parameters
///
/// * `text` - Log-safe fragment text, borrowed or owned.
/// * `completion` - Completion established by session admission and rendering.
///
/// # Returns
///
/// An owned output preserving complete, non-empty truncated, and empty
/// exhausted invariants.
fn redaction_output(text: crate::LogSafeText<'_>, completion: RedactionCompletion) -> RedactionOutput {
    let text = crate::LogSafeText::from_escaped(Cow::Owned(text.into_owned()));
    match completion {
        RedactionCompletion::Complete => RedactionOutput::complete(text),
        RedactionCompletion::Truncated => RedactionOutput::truncated(text).unwrap_or_else(RedactionOutput::exhausted),
        RedactionCompletion::Exhausted => RedactionOutput::exhausted(),
    }
}

/// Maps a rejected session admission to its externally meaningful completion.
///
/// # Parameters
///
/// * `admission` - Admission that rejected rendering of the original input.
///
/// # Returns
///
/// `Truncated` for a non-empty fallback or `Exhausted` when no fallback fit.
fn redaction_admission_completion(admission: RedactionAdmission) -> RedactionCompletion {
    match admission {
        RedactionAdmission::Fallback => RedactionCompletion::Truncated,
        RedactionAdmission::Exhausted => RedactionCompletion::Exhausted,
        RedactionAdmission::Render { .. } => {
            unreachable!("render admissions have no fallback completion")
        }
    }
}

/// Maps an admitted fragment's internal completion to its public semantics.
///
/// # Parameters
///
/// * `text` - Safe fragment text produced by rendering or fallback.
/// * `completion` - Internal completion charged to the shared session.
///
/// # Returns
///
/// `Complete` for a full fragment, `Truncated` for non-empty substitute text,
/// or `Exhausted` when truncation emitted no safe text.
fn redaction_fragment_completion(text: &str, completion: FragmentCompletion) -> RedactionCompletion {
    match completion {
        FragmentCompletion::Complete => RedactionCompletion::Complete,
        FragmentCompletion::DomainTruncated | FragmentCompletion::SessionTruncated if text.is_empty() => {
            RedactionCompletion::Exhausted
        }
        FragmentCompletion::DomainTruncated | FragmentCompletion::SessionTruncated => RedactionCompletion::Truncated,
    }
}

/// Redacts one field through the supplied ordinary or diagnostic budget.
#[must_use]
fn redact_field_with_budget<'value>(
    policy: &RedactionPolicy,
    budget: &mut DiagnosticBudget,
    field: &str,
    value: &'value str,
) -> FieldRedaction<'value> {
    let fallback = opaque_mask(policy);
    let fallback_bytes = log_safe_len(fallback);
    let input_bytes = field.len().saturating_add(value.len());
    let admission = budget.admit(input_bytes, usize::MAX, fallback_bytes);
    let RedactionAdmission::Render { max_output_bytes } = admission else {
        return admission_field_fallback(admission, fallback);
    };

    let (redacted, mask_truncated) = redact_field_unbudgeted(policy, field, value, max_output_bytes);
    let output_bytes = log_safe_len(redacted.as_str());
    if output_bytes <= max_output_bytes {
        let completion = if mask_truncated {
            FragmentCompletion::SessionTruncated
        } else {
            FragmentCompletion::Complete
        };
        budget.commit_output(output_bytes, completion);
        return redacted;
    }
    terminal_field_fallback(budget, max_output_bytes, fallback, fallback_bytes)
}

/// Resolves one admitted field without charging its output.
#[must_use]
fn redact_field_unbudgeted<'value>(
    policy: &RedactionPolicy,
    field: &str,
    value: &'value str,
    max_output_bytes: usize,
) -> (FieldRedaction<'value>, bool) {
    match policy.resolve_field(field) {
        ResolvedField::Sensitive { sensitivity } => {
            let (masked, truncated) =
                policy
                    .masking()
                    .mask_bounded_with_truncation(sensitivity, value, max_output_bytes);
            (
                FieldRedaction::Masked {
                    value: MaskedValue::new(masked),
                    sensitivity,
                },
                truncated,
            )
        }
        ResolvedField::PassThrough => {
            let reason = match policy.classify_field(field) {
                FieldClassification::Allowed { .. } => PassThroughReason::Allowed,
                FieldClassification::Sensitive { .. } | FieldClassification::Unknown => PassThroughReason::Unknown,
            };
            (FieldRedaction::PassedThrough { value, reason }, false)
        }
    }
}

/// Redacts one explicitly sensitive value through a supplied budget.
#[must_use]
fn redact_at_with_budget<'value>(
    policy: &RedactionPolicy,
    budget: &mut DiagnosticBudget,
    level: Sensitivity,
    value: &'value str,
) -> MaskedValue<'value> {
    let fallback = opaque_mask(policy);
    let fallback_bytes = log_safe_len(fallback);
    let admission = budget.admit(value.len(), usize::MAX, fallback_bytes);
    let RedactionAdmission::Render { max_output_bytes } = admission else {
        return admission_text_fallback(admission, fallback);
    };
    let (masked, mask_truncated) = policy
        .masking()
        .mask_bounded_with_truncation(level, value, max_output_bytes);
    let output_bytes = log_safe_len(masked.as_ref());
    if output_bytes <= max_output_bytes {
        let completion = if mask_truncated {
            FragmentCompletion::SessionTruncated
        } else {
            FragmentCompletion::Complete
        };
        budget.commit_output(output_bytes, completion);
        return MaskedValue::new(masked);
    }
    terminal_text_fallback(budget, max_output_bytes, fallback, fallback_bytes)
}

/// Returns the policy's opaque Secret mask.
#[inline(always)]
fn opaque_mask(policy: &RedactionPolicy) -> &str {
    policy.masking().mask_opaque(Sensitivity::Secret)
}

/// Converts a non-render admission into fail-closed redacted text.
#[must_use]
fn admission_text_fallback<'value>(admission: RedactionAdmission, fallback: &str) -> MaskedValue<'value> {
    match admission {
        RedactionAdmission::Fallback => MaskedValue::new(Cow::Owned(fallback.to_owned())),
        RedactionAdmission::Exhausted => MaskedValue::new(Cow::Owned(String::new())),
        RedactionAdmission::Render { .. } => {
            unreachable!("render admissions are handled before fallback")
        }
    }
}

/// Converts a non-render admission into a fail-closed field result.
#[must_use]
fn admission_field_fallback<'value>(admission: RedactionAdmission, fallback: &str) -> FieldRedaction<'value> {
    FieldRedaction::Masked {
        value: admission_text_fallback(admission, fallback),
        sensitivity: Sensitivity::Secret,
    }
}

/// Commits a terminal scalar fallback after rendered output exceeded its cap.
#[must_use]
fn terminal_text_fallback<'value>(
    budget: &mut DiagnosticBudget,
    max_output_bytes: usize,
    fallback: &str,
    fallback_bytes: usize,
) -> MaskedValue<'value> {
    if fallback_bytes <= max_output_bytes {
        budget.commit_output(fallback_bytes, FragmentCompletion::SessionTruncated);
        MaskedValue::new(Cow::Owned(fallback.to_owned()))
    } else {
        budget.commit_output(0, FragmentCompletion::SessionTruncated);
        MaskedValue::new(Cow::Owned(String::new()))
    }
}

/// Wraps a terminal scalar fallback as a field result.
#[must_use]
fn terminal_field_fallback<'value>(
    budget: &mut DiagnosticBudget,
    max_output_bytes: usize,
    fallback: &str,
    fallback_bytes: usize,
) -> FieldRedaction<'value> {
    FieldRedaction::Masked {
        value: terminal_text_fallback(budget, max_output_bytes, fallback, fallback_bytes),
        sensitivity: Sensitivity::Secret,
    }
}

/// Commits a terminal scalar fallback through a diagnostic session.
#[must_use]
fn terminal_session_text_fallback<'value>(
    session: &mut RedactionSession<'_>,
    max_output_bytes: usize,
    fallback: &str,
    fallback_bytes: usize,
    completion: FragmentCompletion,
) -> MaskedValue<'value> {
    if fallback_bytes <= max_output_bytes {
        session.commit_output(fallback_bytes, completion);
        MaskedValue::new(Cow::Owned(fallback.to_owned()))
    } else {
        session.commit_output(0, completion);
        MaskedValue::new(Cow::Owned(String::new()))
    }
}

/// Wraps a session-terminal scalar fallback as a field result.
#[must_use]
fn terminal_session_field_fallback<'value>(
    session: &mut RedactionSession<'_>,
    max_output_bytes: usize,
    fallback: &str,
    fallback_bytes: usize,
    completion: FragmentCompletion,
) -> FieldRedaction<'value> {
    FieldRedaction::Masked {
        value: terminal_session_text_fallback(session, max_output_bytes, fallback, fallback_bytes, completion),
        sensitivity: Sensitivity::Secret,
    }
}

/// Distinguishes a domain-local ceiling from shared session exhaustion.
#[inline(always)]
fn truncation_completion(domain_output_limit: usize, session_output_bytes: usize) -> FragmentCompletion {
    if domain_output_limit < session_output_bytes {
        FragmentCompletion::DomainTruncated
    } else {
        FragmentCompletion::SessionTruncated
    }
}

/// Returns the exact UTF-8 byte length emitted after crossing the log boundary.
#[inline]
#[must_use]
fn log_safe_len(value: &str) -> usize {
    MaskedValue::new(Cow::Borrowed(value)).escape_for_log().as_str().len()
}

impl Default for Redactor {
    /// Creates a redactor from the current global redaction configuration.
    ///
    /// # Returns
    ///
    /// A redactor that is unaffected by later policy configuration attempts.
    /// Before the application installs a global policy this is the fixed
    /// standard baseline, not an application-specific coverage guarantee.
    /// Applications requiring stricter handling must install their complete
    /// policy before construction or pass an explicit policy to [`Self::new`].
    #[inline(always)]
    fn default() -> Self {
        Self::current_default()
    }
}
