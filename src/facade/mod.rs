// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! User-facing redaction facades.

mod default_redactor;
mod redacted_text;
mod redaction_output;
mod redaction_summary;
pub(crate) mod redactor;

pub use redacted_text::RedactedText;
pub use redaction_output::RedactionOutput;
pub use redaction_summary::RedactionReason;
pub use redaction_summary::RedactionReasons;
pub use redaction_summary::RedactionSummary;
pub use redaction_summary::RedactionUsage;
pub use redactor::Redactor;
