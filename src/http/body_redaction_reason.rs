// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Fail-closed reasons for an HTTP body redaction.

/// Identifies why an HTTP body could not be represented structurally.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyRedactionReason {
    /// The shared diagnostic session could not inspect or emit this body.
    DiagnosticBudgetExceeded,
    /// The `Content-Type` header could not be interpreted safely.
    InvalidContentType,
    /// A complete JSON body was invalid.
    InvalidJson,
    /// A JSON capture was invalid or truncated.
    InvalidOrTruncatedJson,
    /// A complete newline-delimited JSON body was invalid.
    InvalidNdjson,
    /// A newline-delimited JSON capture was invalid or truncated.
    InvalidOrTruncatedNdjson,
    /// A complete URL-encoded form body was invalid.
    InvalidFormUrlEncoded,
    /// A URL-encoded form capture was invalid or truncated.
    InvalidOrTruncatedFormUrlEncoded,
    /// A complete multipart body was malformed or ambiguous.
    InvalidMultipart,
    /// A multipart capture was truncated and could not be parsed safely.
    TruncatedMultipart,
    /// A UTF-8 body used an unsupported media type.
    UnsupportedMediaType,
    /// An opaque text body was hidden by policy.
    OpaqueText,
}
