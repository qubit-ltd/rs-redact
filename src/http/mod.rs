// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable HTTP redaction policy, bounded body input, and safe results.

mod body_budget;
mod body_budget_error;
mod body_capture;
mod body_capture_error;
mod body_redaction;
mod body_redaction_reason;
mod body_redaction_status;
mod context_rules_builder;
mod field_redactor;
mod http_field_context;
mod http_redaction_policy;
mod http_redaction_policy_builder;
mod http_redaction_policy_parts;
mod http_redactor;
mod internal;
mod redacted_headers;
mod text_body_policy;
mod unkeyed_json_value_policy;
mod url_path_policy;

pub use crate::{
    DiagnosticBudget,
    DiagnosticBudgetError,
    JsonDepthBudget,
    JsonDepthBudgetError,
};
pub use body_budget::BodyBudget;
pub use body_budget_error::BodyBudgetError;
pub use body_capture::BodyCapture;
pub use body_capture_error::BodyCaptureError;
pub use body_redaction::BodyRedaction;
pub use body_redaction_reason::BodyRedactionReason;
pub use body_redaction_status::BodyRedactionStatus;
pub(in crate::http) use field_redactor::FieldRedactor;
pub use http_field_context::HttpFieldContext;
pub use http_redaction_policy::HttpRedactionPolicy;
pub use http_redaction_policy_builder::HttpRedactionPolicyBuilder;
pub use http_redactor::HttpRedactor;
pub use redacted_headers::RedactedHeaders;
pub use text_body_policy::TextBodyPolicy;
pub use unkeyed_json_value_policy::UnkeyedJsonValuePolicy;
pub use url_path_policy::UrlPathPolicy;
