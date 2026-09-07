// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Structured HTTP body state retained between admission and rendering.

use serde_json::Value;

use super::AdmittedMultipart;

/// Structured body state retained between admission and rendering.
pub(in crate::formats::http) enum AdmittedBody {
    /// The body is not one complete top-level JSON document.
    Other,
    /// One top-level JSON document admitted under the shared budgets.
    Json(
        /// Parsed tree retained so rendering does not parse the input again.
        Value,
    ),
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
    /// A multipart body whose nested structured parts were admitted once.
    Multipart(
        /// Retained admitted multipart structure and nested parsed bodies.
        AdmittedMultipart,
    ),
}
