// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Independent resource budgets exercised by controlled refusal cases.

/// Selects the single resource budget forced to refuse a controlled input.
#[derive(Clone, Copy)]
pub(super) enum StructuralLimit {
    /// Refuse traversal before visiting any node.
    Nodes,
    /// Refuse traversal at the root depth.
    Depth,
    /// Refuse collection elements before processing any item.
    Collection,
    /// Prevent any encoded output bytes from being emitted.
    Output,
}
