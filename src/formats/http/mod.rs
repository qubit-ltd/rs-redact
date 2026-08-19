// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable HTTP redaction policy, bounded body input, and safe results.

mod body_capture;
mod body_capture_error;
mod context_rules_builder;
mod field_redactor;
mod http_field_context;
mod http_redaction_policy;
mod http_redaction_policy_builder;
mod http_redaction_policy_parts;
mod http_redaction_writer;
mod http_redactor;
mod internal;
mod text_body_policy;
mod unkeyed_json_value_policy;
mod url_path_policy;

pub use body_capture::BodyCapture;
pub use body_capture_error::BodyCaptureError;
pub(in crate::formats::http) use field_redactor::FieldRedactor;
pub(crate) use http_field_context::HttpFieldContext;
pub use http_redaction_policy::HttpPolicy;
pub(crate) use http_redaction_policy_builder::HttpPolicyBuilder;
pub use http_redaction_writer::HttpRedactionWriter;
pub use text_body_policy::TextBodyPolicy;
pub use unkeyed_json_value_policy::UnkeyedJsonValuePolicy;
pub use url_path_policy::UrlPathPolicy;
mod body_render_reason;
mod body_render_status;
pub(in crate::formats::http) use body_render_reason::BodyRenderReason;
pub(in crate::formats::http) use body_render_status::BodyRenderStatus;
