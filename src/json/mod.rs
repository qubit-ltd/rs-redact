// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Policy-aware redaction for parsed JSON values and JSON stored as text.

pub(crate) mod internal;

mod json_redaction_session;
mod redact_json_text_in_place;
mod redacted_json;
mod redacted_json_text;

pub use json_redaction_session::JsonRedactionSession;
pub use redact_json_text_in_place::redact_json_text_in_place;
pub use redacted_json::RedactedJson;
pub use redacted_json_text::RedactedJsonText;
