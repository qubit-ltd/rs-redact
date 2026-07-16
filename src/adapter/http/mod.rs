// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! HTTP-specific sanitization adapters.

mod body_bytes;
mod body_redaction_reason;
mod body_sanitization;
mod body_sanitization_status;
mod content_type;
mod http_body_sanitizer;
mod http_header_sanitizer;
mod internal;
mod multipart;
mod redaction_markers;
mod text_body_policy;

pub use body_redaction_reason::BodyRedactionReason;
pub use body_sanitization::BodySanitization;
pub use body_sanitization_status::BodySanitizationStatus;
pub use http_body_sanitizer::HttpBodySanitizer;
pub use http_header_sanitizer::HttpHeaderSanitizer;
pub use text_body_policy::TextBodyPolicy;
