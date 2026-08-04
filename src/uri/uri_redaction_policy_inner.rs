// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared immutable state for URI redaction policies.

use super::{
    UriFragmentPolicy,
    UriPathPolicy,
};

/// Shared immutable URI policy state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UriPolicyInner {
    pub(crate) path_policy: UriPathPolicy,
    pub(crate) fragment_policy: UriFragmentPolicy,
}
