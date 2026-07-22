// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Typed text values that distinguish redacted data from log-safe output.

pub(crate) mod log_escape;
mod log_safe_text;
mod redacted_debug;
mod redacted_text;

pub use log_safe_text::LogSafeText;
pub use redacted_debug::{
    RedactedDebug,
    redacted_debug,
};
pub use redacted_text::RedactedText;
