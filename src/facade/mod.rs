// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! User-facing redaction facades.

mod debug_display;
mod default_redactor;
mod diagnostic_redaction_batch;
mod diagnostic_redaction_batch_output;
mod diagnostic_redaction_handle;
mod diagnostic_redaction_handle_error;
mod diagnostic_redaction_output;
mod redacted_text;
mod redacted_text_composer;
mod redacted_view;
mod redaction_inspection;
mod redaction_inspection_error;
mod redaction_reason;
mod redaction_reasons;
mod redaction_summary;
mod redaction_text_output;
mod redaction_usage;
pub(crate) mod redactor;

pub use debug_display::DebugDisplay;
pub use diagnostic_redaction_batch::DiagnosticRedactionBatch;
pub(crate) use diagnostic_redaction_batch_output::DiagnosticRedactionBatchOutput;
pub use diagnostic_redaction_handle::DiagnosticRedactionHandle;
pub(crate) use diagnostic_redaction_handle_error::DiagnosticRedactionHandleError;
pub use diagnostic_redaction_output::DiagnosticRedactionOutput;
pub use redacted_text::RedactedText;
pub use redacted_text_composer::RedactedTextComposer;
pub use redacted_view::RedactedView;
pub use redaction_inspection::RedactionInspection;
pub use redaction_inspection_error::RedactionInspectionError;
pub use redaction_reason::RedactionReason;
pub use redaction_reasons::RedactionReasons;
pub use redaction_summary::RedactionSummary;
pub use redaction_text_output::RedactionTextOutput;
pub use redaction_usage::RedactionUsage;
pub use redactor::Redactor;
