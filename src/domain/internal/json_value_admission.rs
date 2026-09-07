// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Stack entries for bounded traversal of an already decoded JSON tree.

use serde_json::Value;

/// Schedules structural admission and matching depth release without recursion.
pub(super) enum JsonValueAdmission<'value> {
    /// Admits a node and schedules its descendants and depth release.
    Enter(
        /// Borrowed JSON node retained by the owning decoded tree.
        &'value Value,
    ),
    /// Charges a collection entry before scheduling the referenced node.
    Child(
        /// Child whose collection and node admission have not yet run.
        &'value Value,
    ),
    /// Releases one depth slot previously admitted by Enter.
    Leave,
}
