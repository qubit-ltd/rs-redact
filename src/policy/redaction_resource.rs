// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Resource kinds charged by bounded redaction operations.

/// Resources charged while rendering one redaction event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RedactionResource {
    /// Complete source bytes inspected by one redaction operation.
    Input,
    /// Complete log-safe bytes emitted by one redaction operation.
    Output,
    /// Bytes materialized by generated masks inside a bounded renderer.
    Mask,
}
