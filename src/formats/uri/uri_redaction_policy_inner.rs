// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared immutable state for URI redaction policies.
// qubit-style: allow type-file-name

use super::UriFragmentPolicy;
use super::UriPathPolicy;

/// Shared immutable URI policy state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UriPolicyInner {
    /// Immutable visibility rule for path components.
    pub(crate) path_policy: UriPathPolicy,
    /// Immutable visibility rule for URI fragments.
    pub(crate) fragment_policy: UriFragmentPolicy,
}
