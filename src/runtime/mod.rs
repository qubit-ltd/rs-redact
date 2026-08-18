// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared execution-time accounting for bounded redaction operations.

mod internal;
mod redaction_session;
mod redaction_session_error;
mod redaction_session_output;

pub(crate) use crate::domain::internal::{DomainRedactionContext, DomainTruncation, DomainTruncationCheckpoint, DomainValueBudgetAdmission};
pub use redaction_session::RedactionSession;
pub use redaction_session_error::RedactionSessionError;
pub use redaction_session_output::RedactionSessionOutput;
