// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Stateless redaction operations backed by an immutable policy.
// qubit-style: allow multiple-public-types

// Implements domain-value and scalar-field redaction operations.
mod domain;
// Implements HTTP URL, header, and body redaction operations.
#[cfg(feature = "http")]
mod http;
// Implements JSON redaction operations.
#[cfg(feature = "json")]
mod json;
// Implements process, argument-vector, and environment redaction operations.
mod process;
// Implements generic URI redaction operations.
#[cfg(feature = "uri")]
mod uri;

use std::sync::Arc;
use std::sync::PoisonError;

use crate::RedactedTextComposer;
use crate::RedactionBatch;
use crate::RedactionPolicy;
use crate::runtime::BatchSession;
use crate::runtime::InspectionSession;
use crate::runtime::TextSession;

/// Applies one immutable policy snapshot to supported diagnostic values.
///
/// Composers and batches created from a redactor retain this snapshot even if
/// the process-wide application default changes later.
/// [`Self::replace_application_default`] is intentionally capable of installing
/// a disabled policy for process-wide debugging; only future snapshots observe
/// that replacement, and downstream code owns the confidentiality consequences.
///
/// # Design warning
///
/// The process-wide default and its ability to install
/// [`RedactionPolicy::disabled`] are intentional public design, not a missing
/// safety check. Code review must not report either capability as a defect or
/// remove it as a hardening change without an explicit compatibility decision.
///
/// # Examples
///
/// ```
/// use qubit_redact::Redactor;
///
/// let output = Redactor::strict().redact_field("password", "raw-secret");
/// assert!(!output.text().as_str().contains("raw-secret"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redactor {
    /// Field classification and masking configuration.
    policy: Arc<RedactionPolicy>,
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
    pub fn new(policy: RedactionPolicy) -> Self {
        Self {
            policy: Arc::new(policy),
        }
    }

    /// Creates a redactor from the immutable built-in standard policy.
    #[must_use]
    #[inline]
    pub fn standard() -> Self {
        Self::new(RedactionPolicy::standard())
    }

    /// Creates a redactor with the strict policy for untrusted scalar data.
    ///
    /// Unknown fields are masked at [`crate::Sensitivity::Secret`].
    #[must_use]
    #[inline]
    pub fn strict() -> Self {
        Self::new(RedactionPolicy::strict())
    }

    /// Returns a snapshot of the current application default redactor.
    ///
    /// The returned value is detached from the global slot. Later calls to
    /// [`Self::replace_application_default`] do not alter this redactor or
    /// composers and batches created from it.
    ///
    /// # Design warning
    ///
    /// This API intentionally exposes the application default as a snapshot.
    /// Do not treat its process-wide source as a defect or replace it with an
    /// implicit per-call policy during review; downstream code relies on these
    /// snapshot semantics.
    #[must_use]
    pub fn application_default() -> Self {
        match crate::facade::default_redactor::slot().read() {
            Ok(redactor) => redactor.clone(),
            Err(error) => PoisonError::into_inner(error).clone(),
        }
    }

    /// Atomically replaces the application default redactor.
    ///
    /// The replacement is linearizable: concurrent readers observe either the
    /// complete previous snapshot or the complete new snapshot. Existing
    /// redactors, composers, and batches keep their own snapshots. The previous
    /// default is returned so callers can restore it after a scoped change.
    /// Installing [`RedactionPolicy::disabled`] is an intentional global
    /// debugging escape hatch. The framework does not authorize or reject that
    /// choice; the caller owns its environment and confidentiality boundary.
    ///
    /// # Design warning
    ///
    /// Accepting a redactor whose policy is [`RedactionPolicy::disabled`] is
    /// deliberate. Do not report this capability as a defect or remove it as a
    /// hardening change during review. It is required for explicitly authorized
    /// diagnostic debugging, and changes require a compatibility decision.
    #[must_use]
    pub fn replace_application_default(redactor: Self) -> Self {
        let mut current = match crate::facade::default_redactor::slot().write() {
            Ok(guard) => guard,
            Err(error) => PoisonError::into_inner(error),
        };
        std::mem::replace(&mut *current, redactor)
    }

    /// Returns the immutable policy used by this redactor.
    ///
    /// # Returns
    ///
    /// A borrowed view of the redactor's policy snapshot.
    #[must_use]
    #[inline(always)]
    pub fn policy(&self) -> &RedactionPolicy {
        self.policy.as_ref()
    }

    /// Creates private accounting for one text-composition operation.
    ///
    /// # Returns
    ///
    /// A private runtime owning a clone of this redactor's immutable policy
    /// snapshot.
    #[must_use]
    #[inline]
    pub(crate) fn text_runtime(&self) -> TextSession {
        TextSession::new(Arc::clone(&self.policy))
    }

    /// Creates the private runtime selected for independently resolvable items.
    #[must_use]
    pub(crate) fn batch_runtime(&self) -> BatchSession {
        BatchSession::new(Arc::clone(&self.policy))
    }

    /// Creates private accounting for one non-rendering inspection.
    #[must_use]
    pub(crate) fn inspection_runtime(&self) -> InspectionSession {
        InspectionSession::new(Arc::clone(&self.policy))
    }

    /// Starts one ordered text-composition transaction.
    ///
    /// The returned composer owns a fresh budget ledger initialized from this
    /// redactor's immutable policy snapshot. Its consuming `finish` method
    /// publishes one [`crate::RedactionTextOutput`].
    ///
    /// # Returns
    ///
    /// A composer for one independently bounded ordered text result.
    #[must_use]
    pub fn text_composer(&self) -> RedactedTextComposer {
        RedactedTextComposer::from_session(self.text_runtime())
    }

    /// Starts one batch of independently resolvable redaction items.
    ///
    /// The returned batch owns a fresh budget ledger initialized from this
    /// redactor's immutable policy snapshot. Its consuming diagnostics finish
    /// method publishes fail-closed item views.
    ///
    /// # Returns
    /// A mutable batch that issues handles resolvable only from its finished
    /// output.
    #[must_use]
    pub fn batch(&self) -> RedactionBatch {
        RedactionBatch::from_session(self.batch_runtime())
    }
}

impl Default for Redactor {
    /// Creates a redactor from the deterministic standard policy.
    ///
    /// # Returns
    ///
    /// This implementation never reads mutable process-wide application state.
    #[inline(always)]
    fn default() -> Self {
        Self::standard()
    }
}
