// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Private fail-closed reasons used while rendering an HTTP body.

/// Explains why HTTP body rendering used a fail-closed representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::formats::http) enum BodyRenderReason {
    /// The declared content type could not be parsed safely.
    InvalidContentType,
    /// A JSON body is syntactically invalid.
    InvalidJson,
    /// JSON input is invalid or source-truncated.
    InvalidOrTruncatedJson,
    /// An NDJSON body is syntactically invalid.
    InvalidNdjson,
    /// NDJSON input is invalid or source-truncated.
    InvalidOrTruncatedNdjson,
    /// A form body is syntactically invalid.
    InvalidFormUrlEncoded,
    /// Form input is invalid or source-truncated.
    InvalidOrTruncatedFormUrlEncoded,
    /// A multipart body is syntactically invalid.
    InvalidMultipart,
    /// Multipart source capture was truncated.
    TruncatedMultipart,
    /// The content type has no safe structured renderer.
    UnsupportedMediaType,
    /// Plain text must be represented as opaque output.
    OpaqueText,
}
