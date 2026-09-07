// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Parsed structured payload retained for a nested multipart body.

use serde_json::Value;

/// One nested structured multipart body retained by admission.
pub(in crate::formats::http) enum AdmittedMultipartBody {
    /// One complete JSON value.
    Json(
        /// Parsed nested tree reused by rendering without another parse.
        Value,
    ),
    /// NDJSON records preserving empty lines and final newline state.
    Ndjson {
        /// Parsed source records in order.
        lines: Vec<Option<Value>>,
        /// Whether the source ended with a newline.
        trailing_newline: bool,
    },
}
