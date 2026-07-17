// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Redaction marker constants shared by HTTP body helpers.

/// Redaction marker for invalid complete JSON bodies.
pub(super) const INVALID_JSON_REDACTED: &str = "<redacted: invalid JSON>";
/// Redaction marker for invalid or truncated JSON previews.
pub(super) const INVALID_OR_TRUNCATED_JSON_REDACTED: &str =
    "<redacted: invalid or truncated JSON>";
/// Redaction marker for invalid complete NDJSON bodies.
pub(super) const INVALID_NDJSON_REDACTED: &str = "<redacted: invalid NDJSON>";
/// Redaction marker for invalid or truncated NDJSON previews.
pub(super) const INVALID_OR_TRUNCATED_NDJSON_REDACTED: &str =
    "<redacted: invalid or truncated NDJSON>";
/// Redaction marker for JSON scalar values without an object-field context.
pub(super) const UNKEYED_JSON_VALUE_REDACTED: &str =
    "<redacted: unkeyed JSON value>";
/// Redaction marker for invalid complete URL-encoded form bodies.
pub(super) const INVALID_FORM_URLENCODED_REDACTED: &str =
    "<redacted: invalid URL-encoded form>";
/// Redaction marker for invalid or truncated URL-encoded form previews.
pub(super) const INVALID_OR_TRUNCATED_FORM_URLENCODED_REDACTED: &str =
    "<redacted: invalid or truncated URL-encoded form>";
/// Redaction marker for bodies whose Content-Type cannot be interpreted.
pub(super) const INVALID_CONTENT_TYPE_REDACTED: &str =
    "<redacted: invalid content type body>";
/// Redaction marker for UTF-8 bodies without a supported structured or text
/// media type.
pub(super) const UNSUPPORTED_BODY_REDACTED: &str =
    "<redacted: unsupported HTTP body>";
/// Redaction marker for declared top-level text bodies.
pub(super) const TEXT_BODY_REDACTED: &str = "<redacted: text body>";
/// Redaction marker for multipart bodies that cannot be safely summarized.
pub(super) const MULTIPART_BODY_REDACTED: &str = "<redacted: multipart body>";
/// Redaction marker for multipart parts that cannot be safely rendered.
pub(super) const MULTIPART_PART_REDACTED: &str = "<redacted: multipart part>";
/// Redaction marker for non-sensitive multipart text parts.
pub(super) const MULTIPART_TEXT_PART_REDACTED: &str =
    "<redacted: multipart text part>";
/// Redaction marker for multipart file parts.
pub(super) const MULTIPART_FILE_PART_REDACTED: &str = "<redacted: file part>";
/// Placeholder field name used for unnamed multipart parts.
pub(super) const MULTIPART_UNNAMED_FIELD: &str = "<unnamed>";
