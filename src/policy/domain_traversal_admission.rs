// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Admission result for one domain field or collection item.

/// Reports whether a caller may access the next domain traversal unit.
#[must_use = "inspect the admission before accessing the field or collection item"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainTraversalAdmission {
    /// The caller may access and render the field or collection item.
    Render,
    /// The cumulative traversal budget is exhausted; no value may be accessed.
    LimitReached,
}
