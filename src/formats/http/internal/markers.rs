// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Fixed fail-closed HTTP markers.

/// Appended when bounded output omits source data.
pub(in crate::formats::http) const TRUNCATED: &str = "<truncated>";
/// Replaces a URL that cannot be parsed safely.
pub(in crate::formats::http) const INVALID_URL: &str = "<redacted: invalid URL>";
/// Replaces a URL whose nested encoding exceeds the recursion limit.
pub(in crate::formats::http) const NESTED_URL_LIMIT: &str = "<redacted: nested URL limit exceeded>";
/// Replaces a malformed URL-encoded query.
pub(in crate::formats::http) const INVALID_QUERY: &str = "<redacted: invalid URL-encoded query>";
/// Replaces a malformed URL-encoded form.
pub(in crate::formats::http) const INVALID_FORM: &str = "<redacted: invalid URL-encoded form>";
/// Replaces a malformed or incomplete URL-encoded form body.
pub(in crate::formats::http) const INVALID_OR_TRUNCATED_FORM: &str =
    "<redacted: invalid or truncated URL-encoded form>";
/// Replaces a body whose content type cannot be parsed safely.
pub(in crate::formats::http) const INVALID_CONTENT_TYPE: &str = "<redacted: invalid content type body>";
/// Replaces malformed JSON input.
pub(in crate::formats::http) const INVALID_JSON: &str = "<redacted: invalid JSON>";
/// Replaces malformed or incomplete JSON input.
pub(in crate::formats::http) const INVALID_OR_TRUNCATED_JSON: &str = "<redacted: invalid or truncated JSON>";
/// Replaces malformed newline-delimited JSON input.
pub(in crate::formats::http) const INVALID_NDJSON: &str = "<redacted: invalid NDJSON>";
/// Replaces malformed or incomplete newline-delimited JSON input.
pub(in crate::formats::http) const INVALID_OR_TRUNCATED_NDJSON: &str = "<redacted: invalid or truncated NDJSON>";
/// Replaces a JSON value that has no field name for classification.
pub(in crate::formats::http) const UNKEYED_JSON: &str = "<redacted: unkeyed JSON value>";
/// Replaces an HTTP body format that the redactor does not support.
pub(in crate::formats::http) const UNSUPPORTED_BODY: &str = "<redacted: unsupported HTTP body>";
/// Replaces opaque text when pass-through is not enabled.
pub(in crate::formats::http) const TEXT_BODY: &str = "<redacted: text body>";
/// Replaces a multipart body that cannot be processed safely.
pub(in crate::formats::http) const MULTIPART_BODY: &str = "<redacted: multipart body>";
/// Replaces a malformed or unsupported multipart part.
pub(in crate::formats::http) const MULTIPART_PART: &str = "<redacted: multipart part>";
/// Replaces an opaque multipart text part.
pub(in crate::formats::http) const MULTIPART_TEXT: &str = "<redacted: multipart text part>";
/// Replaces multipart file contents.
pub(in crate::formats::http) const MULTIPART_FILE: &str = "<redacted: file part>";
/// Labels a multipart part whose field name is absent.
pub(in crate::formats::http) const MULTIPART_UNNAMED: &str = "<unnamed>";
