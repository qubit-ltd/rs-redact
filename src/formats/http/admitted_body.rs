// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Structured HTTP body state retained between admission and rendering.

use serde_json::Value;

/// Structured body state retained between admission and rendering.
pub(super) enum AdmittedBody {
    /// The body is not one complete top-level JSON document.
    Other,
    /// One top-level JSON document admitted under the shared budgets.
    Json(Value),
    /// A body selected as JSON failed syntactic validation.
    InvalidJson,
    /// Non-empty NDJSON lines admitted under the shared budgets.
    Ndjson {
        /// Parsed values and empty records in source-line order.
        lines: Vec<Option<Value>>,
        /// Whether the complete source ended with a newline.
        trailing_newline: bool,
    },
    /// A body selected as NDJSON contained an invalid non-empty line.
    InvalidNdjson,
}
