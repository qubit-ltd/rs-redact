// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable URI redaction policy.
// qubit-style: allow type-file-name

use std::sync::Arc;

use super::UriFragmentPolicy;
use super::UriPathPolicy;
use super::uri_redaction_policy_inner::UriPolicyInner;

/// Immutable URI policy that delegates field decisions to the core policy.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UriPolicy {
    pub(crate) inner: Arc<UriPolicyInner>,
}

impl UriPolicy {
    /// Returns the path handling policy.
    #[must_use = "inspect the path policy"]
    #[inline]
    pub fn path_policy(&self) -> UriPathPolicy {
        self.inner.path_policy
    }

    /// Returns the fragment handling policy.
    #[must_use = "inspect the fragment policy"]
    #[inline]
    pub fn fragment_policy(&self) -> UriFragmentPolicy {
        self.inner.fragment_policy
    }

    /// Creates an immutable URI policy from validated component policies.
    pub(crate) fn new(
        path_policy: UriPathPolicy,
        fragment_policy: UriFragmentPolicy,
    ) -> Self {
        Self {
            inner: Arc::new(UriPolicyInner {
                path_policy,
                fragment_policy,
            }),
        }
    }
}
