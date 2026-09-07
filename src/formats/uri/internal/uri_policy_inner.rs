// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared immutable state for URI redaction policies.

use super::super::UriFragmentPolicy;
use super::super::UriPathPolicy;

/// Shared immutable URI policy state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::formats::uri) struct UriPolicyInner {
    /// Immutable visibility rule for path components.
    pub(in crate::formats::uri) path_policy: UriPathPolicy,
    /// Immutable visibility rule for URI fragments.
    pub(in crate::formats::uri) fragment_policy: UriFragmentPolicy,
}
