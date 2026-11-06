// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Marker contract for generated fixed-level value support.

/// Marker used by the `Redact` derive macro for its supported `level` value
/// set.
///
/// This supports generated code but is not an absolute barrier to manual
/// downstream implementations.
pub trait Sealed {
    // empty
}
