// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Errors raised while committing a redaction session.

/// Structural errors that prevent an atomic session from being committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedactionSessionError {
    /// An adapter result was staged with an empty key.
    EmptyKey,
    /// More than one result used the same key.
    DuplicateKey { key: String },
}
