// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Defines the private stop signal for mutable JSON redaction.

/// Stops one mutable JSON traversal after the mask budget is exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JsonRedactionStop;
