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
mod redacted_text_composer;
mod redaction_batch;
mod redaction_batch_diagnostics;
mod redaction_batch_handle;
mod redaction_batch_handle_error;
mod redaction_batch_output;
mod redaction_inspection;
mod redaction_inspection_error;
mod redaction_summary;
mod redaction_text_output;
pub(crate) mod redactor;

pub use redacted_text::RedactedText;
pub use redacted_text_composer::RedactedTextComposer;
pub use redaction_batch::RedactionBatch;
pub use redaction_batch_diagnostics::RedactionBatchDiagnostics;
pub use redaction_batch_handle::RedactionBatchHandle;
pub(crate) use redaction_batch_handle_error::RedactionBatchHandleError;
pub(crate) use redaction_batch_output::RedactionBatchOutput;
pub use redaction_inspection::RedactionInspection;
pub use redaction_inspection_error::RedactionInspectionError;
pub use redaction_summary::RedactionReason;
pub use redaction_summary::RedactionReasons;
pub use redaction_summary::RedactionSummary;
pub use redaction_summary::RedactionUsage;
pub use redaction_text_output::RedactionTextOutput;
pub use redactor::Redactor;
