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
mod json_redaction_session;

pub use json_redaction_session::JsonRedactionSession;
pub(crate) use json_redaction_session::admit_json_text_structure;
pub(crate) use json_redaction_session::redact_json_text_with_limit;
