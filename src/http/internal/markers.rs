// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Fixed fail-closed HTTP markers.

pub(in crate::http) const TRUNCATED: &str = "<truncated>";
pub(in crate::http) const DIAGNOSTIC_LIMIT_EXCEEDED: &str =
    "<redacted: diagnostic limit exceeded>";
pub(in crate::http) const INVALID_URL: &str = "<redacted: invalid URL>";
pub(in crate::http) const NESTED_URL_LIMIT: &str =
    "<redacted: nested URL limit exceeded>";
pub(in crate::http) const INVALID_QUERY: &str =
    "<redacted: invalid URL-encoded query>";
pub(in crate::http) const INVALID_FORM: &str =
    "<redacted: invalid URL-encoded form>";
pub(in crate::http) const INVALID_OR_TRUNCATED_FORM: &str =
    "<redacted: invalid or truncated URL-encoded form>";
pub(in crate::http) const INVALID_CONTENT_TYPE: &str =
    "<redacted: invalid content type body>";
pub(in crate::http) const INVALID_JSON: &str = "<redacted: invalid JSON>";
pub(in crate::http) const INVALID_OR_TRUNCATED_JSON: &str =
    "<redacted: invalid or truncated JSON>";
pub(in crate::http) const INVALID_NDJSON: &str = "<redacted: invalid NDJSON>";
pub(in crate::http) const INVALID_OR_TRUNCATED_NDJSON: &str =
    "<redacted: invalid or truncated NDJSON>";
pub(in crate::http) const UNKEYED_JSON: &str = "<redacted: unkeyed JSON value>";
pub(in crate::http) const UNSUPPORTED_BODY: &str =
    "<redacted: unsupported HTTP body>";
pub(in crate::http) const TEXT_BODY: &str = "<redacted: text body>";
pub(in crate::http) const MULTIPART_BODY: &str = "<redacted: multipart body>";
pub(in crate::http) const MULTIPART_PART: &str = "<redacted: multipart part>";
pub(in crate::http) const MULTIPART_TEXT: &str =
    "<redacted: multipart text part>";
pub(in crate::http) const MULTIPART_FILE: &str = "<redacted: file part>";
pub(in crate::http) const MULTIPART_UNNAMED: &str = "<unnamed>";
