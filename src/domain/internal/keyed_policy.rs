// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared policy lookup for values classified by a runtime key.

use crate::RedactionPolicy;
use crate::policy::ResolvedField;

/// Resolves a runtime key through the active policy.
#[inline]
pub(crate) fn resolve_keyed_field(policy: &RedactionPolicy, key: &str) -> ResolvedField {
    policy.resolve_field(key)
}
