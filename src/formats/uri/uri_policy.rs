// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable URI redaction policy.

use std::sync::Arc;

use super::UriFragmentPolicy;
use super::UriPathPolicy;
use super::internal::UriPolicyInner;

/// Immutable URI policy that delegates field decisions to the core policy.
///
/// # Examples
///
/// ```
/// use qubit_redact::RedactionPolicy;
/// use qubit_redact::formats::uri::UriPathPolicy;
///
/// let policy = RedactionPolicy::strict();
/// assert_eq!(policy.uri().path_policy(), UriPathPolicy::Redact);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UriPolicy {
    /// Shared immutable choices behind cheap policy clones.
    inner: Arc<UriPolicyInner>,
}

impl UriPolicy {
    /// Creates an immutable URI policy from validated component policies.
    ///
    /// # Parameters
    ///
    /// * `path_policy` - Visibility of URI paths.
    /// * `fragment_policy` - Visibility and classification of URI fragments.
    ///
    /// # Returns
    ///
    /// A shared immutable snapshot; cloning it does not copy component state.
    #[must_use]
    #[inline(always)]
    pub(crate) fn new(path_policy: UriPathPolicy, fragment_policy: UriFragmentPolicy) -> Self {
        Self {
            inner: Arc::new(UriPolicyInner {
                path_policy,
                fragment_policy,
            }),
        }
    }

    /// Returns the path handling policy.
    ///
    /// # Returns
    ///
    /// The immutable visibility policy for URI path components.
    #[must_use]
    #[inline(always)]
    pub fn path_policy(&self) -> UriPathPolicy {
        self.inner.path_policy
    }

    /// Returns the fragment handling policy.
    ///
    /// # Returns
    ///
    /// The immutable classification and visibility policy for URI fragments.
    #[must_use]
    #[inline(always)]
    pub fn fragment_policy(&self) -> UriFragmentPolicy {
        self.inner.fragment_policy
    }
}
