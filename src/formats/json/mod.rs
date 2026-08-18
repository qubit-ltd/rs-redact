// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Policy-aware redaction for parsed JSON values and JSON stored as text.

pub(crate) mod internal;

mod bounded_json_redaction;
mod json_redaction_output;
mod json_redaction_session;
mod json_redactor;
mod redacted_json;
mod redacted_json_text;

pub use bounded_json_redaction::redact_json_text_in_place;
pub use json_redaction_output::JsonRedactionOutput;
pub use json_redaction_session::JsonRedactionSession;
pub use json_redactor::JsonRedactor;
pub use redacted_json::RedactedJson;
pub use redacted_json_text::RedactedJsonText;
