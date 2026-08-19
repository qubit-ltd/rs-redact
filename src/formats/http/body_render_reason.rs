// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Private fail-closed reasons used while rendering an HTTP body.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::formats::http) enum BodyRenderReason {
    InvalidContentType,
    InvalidJson,
    InvalidOrTruncatedJson,
    InvalidNdjson,
    InvalidOrTruncatedNdjson,
    InvalidFormUrlEncoded,
    InvalidOrTruncatedFormUrlEncoded,
    InvalidMultipart,
    TruncatedMultipart,
    UnsupportedMediaType,
    OpaqueText,
}
