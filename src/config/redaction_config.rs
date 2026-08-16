// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Complete configuration snapshot used by redaction facades.

use crate::RedactionPolicy;

/// Complete immutable configuration snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionConfig {
    pub(crate) policy: RedactionPolicy,
}

impl RedactionConfig {
    /// Creates the standard configuration.
    #[must_use]
    pub fn standard() -> Self {
        Self {
            policy: RedactionPolicy::standard(),
        }
    }

    /// Creates the strict configuration.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            policy: RedactionPolicy::strict(),
        }
    }

    /// Consumes the configuration and returns its policy snapshot.
    #[must_use]
    pub(crate) fn into_policy(self) -> RedactionPolicy {
        self.policy
    }
}

impl From<RedactionPolicy> for RedactionConfig {
    #[inline]
    fn from(policy: RedactionPolicy) -> Self {
        Self { policy }
    }
}
