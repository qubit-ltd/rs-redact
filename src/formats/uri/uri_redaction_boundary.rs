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
    /// Effective immutable snapshot with confidentiality enabled and the
    /// standard floor.
    policy: RedactionPolicy,
}

impl UriRedactionBoundary {
    /// Creates a boundary from an application policy snapshot.
    #[must_use]
    pub fn new(application: &RedactionPolicy) -> Self {
        let mut policy = application.clone();
        let _ = policy.set_disabled(false);
        policy = policy.with_floor(crate::policy::RedactionFloor::standard());
        policy = policy.with_masking(RedactionPolicy::standard().masking().clone());
        Self { policy }
    }

    /// Returns the effective boundary policy.
    #[must_use]
    #[inline(always)]
    pub fn policy(&self) -> &RedactionPolicy {
        &self.policy
    }

    /// Redacts one URI while preserving safe URI structure.
    #[must_use]
    pub fn redact_uri(&self, text: &str) -> RedactionTextOutput {
        crate::Redactor::new(self.policy.clone()).redact_uri(text)
    }

    /// Inspects one URI under the same mandatory floor.
    ///
    /// # Errors
    ///
    /// Returns an inconclusive inspection on malformed input or budget
    /// rejection.
    pub fn inspect_uri(&self, text: &str) -> Result<RedactionInspection, RedactionInspectionError> {
        crate::Redactor::new(self.policy.clone()).inspect_uri(text)
    }
}
