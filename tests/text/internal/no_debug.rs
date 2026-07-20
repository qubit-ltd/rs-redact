// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! A test value intentionally lacking a debug implementation.

// qubit-style: allow test-file-name

/// Proves redacted debug wrappers do not require the wrapped type to implement
/// [`std::fmt::Debug`].
pub(crate) struct NoDebug;
