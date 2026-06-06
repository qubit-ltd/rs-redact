// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
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
/// Redaction marker for bodies whose Content-Type cannot be interpreted.
pub(super) const INVALID_CONTENT_TYPE_REDACTED: &str =
    "<redacted: invalid content type body>";
/// Redaction marker for UTF-8 bodies without a supported structured or text
/// media type.
pub(super) const UNSUPPORTED_BODY_REDACTED: &str =
    "<redacted: unsupported HTTP body>";
/// Redaction marker for multipart bodies that cannot be safely summarized.
pub(super) const MULTIPART_BODY_REDACTED: &str = "<redacted: multipart body>";
/// Redaction marker for multipart parts that cannot be safely rendered.
pub(super) const MULTIPART_PART_REDACTED: &str = "<redacted: multipart part>";
/// Redaction marker for multipart file parts.
pub(super) const MULTIPART_FILE_PART_REDACTED: &str = "<redacted: file part>";
/// Placeholder field name used for unnamed multipart parts.
pub(super) const MULTIPART_UNNAMED_FIELD: &str = "<unnamed>";
