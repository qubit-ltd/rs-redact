// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! URI boundary redaction with a mandatory standard safety floor.

use crate::RedactionInspection;
use crate::RedactionInspectionError;
use crate::RedactionPolicy;
use crate::RedactionTextOutput;
use crate::Redactor;

/// Applies application URI rules while retaining the standard URI safety
/// floor and standard masks.
///
/// # Examples
///
/// ```
/// use qubit_redact::RedactionPolicy;
/// use qubit_redact::formats::uri::UriRedactionBoundary;
/// let boundary = UriRedactionBoundary::new(&RedactionPolicy::disabled());
/// assert!(!boundary.policy().is_disabled());
/// let output = boundary.redact_uri("https://example.test/?password=raw-secret");
/// assert!(!output.text().as_str().contains("raw-secret"));
/// ```
#[derive(Debug, Clone)]
pub struct UriRedactionBoundary {
    /// Reusable executor with confidentiality enabled and the standard floor.
    redactor: Redactor,
}

impl UriRedactionBoundary {
    /// Creates a boundary from an application policy snapshot.
    ///
    /// The snapshot retains application floors, resource limits, and URI
    /// path and fragment configuration. The standard URI floor is added and
    /// standard masks replace application masks. Confidentiality remains
    /// enabled even when `application` is disabled.
    ///
    /// # Parameters
    ///
    /// - `application`: policy snapshot whose application settings are used
    ///   beneath the mandatory URI safety floor.
    ///
    /// # Returns
    ///
    /// A reusable boundary with confidentiality enabled.
    #[must_use]
    pub fn new(application: &RedactionPolicy) -> Self {
        let mut policy = application.clone();
        let _ = policy.set_disabled(false);
        policy = policy.add_floor(crate::policy::RedactionFloor::standard());
        let standard = RedactionPolicy::standard();
        policy = policy.with_masking(standard.masking());
        Self {
            redactor: Redactor::new(policy),
        }
    }

    /// Returns the effective policy used by this boundary.
    ///
    /// It includes the standard URI floor and masks, preserves application
    /// limits and URI path/fragment configuration, and is never disabled.
    #[inline(always)]
    pub fn policy(&self) -> &RedactionPolicy {
        self.redactor.policy()
    }

    /// Redacts one URI while preserving safe URI structure.
    ///
    /// # Parameters
    ///
    /// - `text`: URI text to redact.
    ///
    /// # Returns
    ///
    /// The bounded redaction output. Check its completion state before using
    /// the text; use a fixed marker when the output is incomplete rather than
    /// falling back to the original URI.
    #[must_use]
    pub fn redact_uri(&self, text: &str) -> RedactionTextOutput {
        self.redactor.redact_uri(text)
    }

    /// Inspects one URI under the same mandatory floor.
    ///
    /// # Parameters
    ///
    /// - `text`: URI text to inspect for admission.
    ///
    /// # Returns
    ///
    /// An inspection result when inspection completes. A successful result
    /// is not a certificate of URI syntax validity; callers deciding whether
    /// to accept a resource location should use this method and also reject
    /// any sensitive result.
    ///
    /// # Errors
    ///
    /// Returns [`RedactionInspectionError`] when parsing is malformed or a
    /// configured resource budget prevents conclusive inspection. Treat any
    /// error as a rejection when deciding whether to accept a URI.
    pub fn inspect_uri(&self, text: &str) -> Result<RedactionInspection, RedactionInspectionError> {
        self.redactor.inspect_uri(text)
    }
}
