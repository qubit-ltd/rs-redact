// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Typed text values that distinguish redacted data from log-safe output.

mod bounded_log_safe_display;
mod diagnostic_log_builder;
pub(crate) mod internal;
pub(crate) mod log_escape;
mod log_output_limit;
mod log_output_limit_error;
mod log_safe_text;
mod redacted_debug;
mod redacted_text;
mod redaction_completion;
pub(crate) mod redaction_output;

pub use bounded_log_safe_display::BoundedLogSafeDisplay;
pub use diagnostic_log_builder::DiagnosticLogBuilder;
pub use log_output_limit::LogOutputLimit;
pub use log_output_limit_error::LogOutputLimitError;
pub use log_safe_text::LogSafeText;
pub use redacted_debug::RedactedDebug;
pub use redacted_debug::redacted_debug;
pub use redacted_text::RedactedText;
pub use redaction_completion::RedactionCompletion;
