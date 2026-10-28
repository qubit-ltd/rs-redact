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

    /// Returns the effective boundary policy.
    #[inline(always)]
    pub fn policy(&self) -> &RedactionPolicy {
        self.redactor.policy()
    }

    /// Redacts one URI while preserving safe URI structure.
    #[must_use]
    pub fn redact_uri(&self, text: &str) -> RedactionTextOutput {
        self.redactor.redact_uri(text)
    }

    /// Inspects one URI under the same mandatory floor.
    ///
    /// # Errors
    ///
    /// Returns an inconclusive inspection on malformed input or budget
    /// rejection.
    pub fn inspect_uri(&self, text: &str) -> Result<RedactionInspection, RedactionInspectionError> {
        self.redactor.inspect_uri(text)
    }
}
