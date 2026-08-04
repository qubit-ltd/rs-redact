// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Policy-aware redaction for parsed JSON values and JSON stored as text.

pub(crate) mod internal;

mod redact_json_text_in_place;
mod redacted_json;
mod redacted_json_text;

pub use redact_json_text_in_place::redact_json_text_in_place;
pub use redacted_json::{
    RedactedJson,
    RedactedJsonSession,
};
pub use redacted_json_text::{
    RedactedJsonText,
    RedactedJsonTextSession,
};
