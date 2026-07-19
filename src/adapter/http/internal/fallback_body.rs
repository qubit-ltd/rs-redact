// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Private fallback sanitization for opaque and binary HTTP bodies.

use super::super::{
    BodyRedactionReason,
    BodySanitization,
    BodySanitizationStatus,
    BodySourceLength,
    content_type,
    redaction_markers::{
        TEXT_BODY_REDACTED,
        UNSUPPORTED_BODY_REDACTED,
    },
    text_body_policy::TextBodyPolicy,
};

/// Sanitizes body bytes that do not match a supported structured format.
///
/// # Parameters
///
/// * `bytes` - Captured body bytes.
/// * `source_length` - Exact or unknown-truncated source length metadata.
/// * `content_type` - Optional declared content type used to recognize opaque
///   text bodies.
/// * `text_body_policy` - Policy for declared UTF-8 text.
///
/// # Returns
///
/// A policy-controlled text result for declared UTF-8 text, an unsupported
/// media-type redaction for other UTF-8 bodies, or a binary byte-count result
/// for non-UTF-8 bodies.
pub(in crate::adapter::http) fn sanitize_fallback_body(
    bytes: &[u8],
    source_length: BodySourceLength,
    content_type: Option<&str>,
    text_body_policy: TextBodyPolicy,
) -> BodySanitization {
    match std::str::from_utf8(bytes) {
        Ok(text) => sanitize_utf8_body(
            text,
            bytes.len(),
            source_length,
            content_type,
            text_body_policy,
        ),
        Err(_) => sanitize_binary_body(bytes.len(), source_length),
    }
}

/// Sanitizes fallback body bytes that are valid UTF-8.
///
/// # Parameters
///
/// * `text` - Decoded UTF-8 body.
/// * `captured_len` - Number of captured body bytes.
/// * `source_length` - Exact or unknown-truncated source length metadata.
/// * `content_type` - Optional declared content type.
/// * `text_body_policy` - Policy for declared text bodies.
///
/// # Returns
///
/// A policy-controlled result for declared text or a fixed unsupported-media
/// redaction for other UTF-8 bodies.
fn sanitize_utf8_body(
    text: &str,
    captured_len: usize,
    source_length: BodySourceLength,
    content_type: Option<&str>,
    text_body_policy: TextBodyPolicy,
) -> BodySanitization {
    if !content_type.is_some_and(content_type::is_text) {
        return BodySanitization::new(
            UNSUPPORTED_BODY_REDACTED.to_string(),
            BodySanitizationStatus::Redacted(
                BodyRedactionReason::UnsupportedMediaType,
            ),
            captured_len,
            source_length,
        );
    }
    let (content, status) = match text_body_policy {
        TextBodyPolicy::Redact => (
            TEXT_BODY_REDACTED.to_string(),
            BodySanitizationStatus::Redacted(BodyRedactionReason::OpaqueText),
        ),
        TextBodyPolicy::PassThrough => {
            (text.to_string(), BodySanitizationStatus::PassedThrough)
        }
    };
    BodySanitization::new(content, status, captured_len, source_length)
}

/// Summarizes fallback body bytes that are not valid UTF-8.
///
/// # Parameters
///
/// * `captured_len` - Number of captured body bytes.
/// * `source_length` - Exact or unknown-truncated source length metadata.
///
/// # Returns
///
/// A binary byte-count result that distinguishes exact and truncated input.
fn sanitize_binary_body(
    captured_len: usize,
    source_length: BodySourceLength,
) -> BodySanitization {
    let (source_len, _) = source_length.resolve(captured_len);
    let content = match source_len {
        Some(source_len) => format!("<binary {source_len} bytes>"),
        None => format!("<binary more than {captured_len} bytes>"),
    };
    BodySanitization::new(
        content,
        BodySanitizationStatus::Binary,
        captured_len,
        source_length,
    )
}
