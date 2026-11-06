// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Supported storage shapes for syntactically self-recursive fields.

/// Identifies the supported outer storage shape for a self-recursive field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::serde) enum RecursiveShape {
    /// The field directly stores the derived type.
    Direct,
    /// The field stores an optional boxed derived type.
    OptionBox,
    /// The field stores boxed derived values in a vector.
    VecBox,
}
