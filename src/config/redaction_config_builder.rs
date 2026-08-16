// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Builder entry point for [`super::RedactionConfig`].

use super::RedactionConfig;
use crate::RedactionPolicyBuilder;

/// Builder for a complete immutable redaction configuration.
#[derive(Debug, Clone)]
pub struct RedactionConfigBuilder {
    inner: RedactionPolicyBuilder,
}

impl RedactionConfigBuilder {
    /// Creates a builder initialized with the standard configuration.
    #[must_use]
    pub fn standard() -> Self {
        Self {
            inner: RedactionPolicyBuilder::new(),
        }
    }

    /// Builds an immutable configuration snapshot.
    pub fn build(self) -> Result<RedactionConfig, crate::PolicyError> {
        self.inner.build().map(Into::into)
    }
}

impl Default for RedactionConfigBuilder {
    fn default() -> Self {
        Self::standard()
    }
}
