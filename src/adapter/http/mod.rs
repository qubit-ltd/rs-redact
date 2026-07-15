// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! HTTP-specific sanitization adapters.

mod body_bytes;
mod body_input_kind;
mod content_type;
mod http_body_sanitizer;
mod http_header_sanitizer;
mod multipart;
mod redaction_markers;
mod text_body_policy;

pub use http_body_sanitizer::HttpBodySanitizer;
pub use http_header_sanitizer::HttpHeaderSanitizer;
pub use text_body_policy::TextBodyPolicy;
