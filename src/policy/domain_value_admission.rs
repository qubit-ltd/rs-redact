// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Admission result for entering one domain value.

use super::DomainValueScope;

/// Reports whether one domain value may be rendered under the shared session.
#[must_use = "inspect the admission before accessing the domain value"]
#[derive(Debug)]
pub enum DomainValueAdmission<'session, 'policy> {
    /// The value was charged and owns one active-depth scope.
    Entered(DomainValueScope<'session, 'policy>),
    /// Only this branch exceeded active depth; sibling traversal may continue.
    DepthLimitReached,
    /// Cumulative node or collection traversal is permanently exhausted.
    TraversalLimitReached,
}
