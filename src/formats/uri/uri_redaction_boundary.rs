// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! URI boundary redaction with a mandatory standard safety floor.

use crate::RedactionInspection;
use crate::RedactionInspectionError;
use crate::RedactionPolicy;
use crate::RedactionTextOutput;

/// Applies application URI rules while retaining the standard URI safety
/// floor and standard masks.
#[derive(Debug, Clone)]
pub struct UriRedactionBoundary {
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
    pub fn policy(&self) -> &RedactionPolicy {
        &self.policy
    }

    /// Redacts one URI while preserving safe URI structure.
    #[must_use]
    pub fn redact_uri(&self, text: &str) -> RedactionTextOutput {
        crate::Redactor::new(self.policy.clone()).redact_uri(text)
    }

    /// Inspects one URI under the same mandatory floor.
    pub fn inspect_uri(&self, text: &str) -> Result<RedactionInspection, RedactionInspectionError> {
        crate::Redactor::new(self.policy.clone()).inspect_uri(text)
    }
}
