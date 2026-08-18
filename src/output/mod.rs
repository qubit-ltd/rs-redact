// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Typed redaction output values and bounded log-safe writers.

pub(crate) mod internal;
pub(crate) mod log_escape;
mod masked_value;
mod redacted_debug;
mod redacted_text;
mod redaction_completion;

pub(crate) use masked_value::MaskedValue;
pub use redacted_debug::RedactedDebug;
pub use redacted_debug::redacted_debug;
pub use redaction_completion::RedactionCompletion;

pub(crate) use crate::facade::RedactedText;
