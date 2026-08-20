// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared execution-time accounting for bounded redaction operations.

mod redaction_budget;
mod redaction_handle;
mod redaction_session;
mod redaction_session_output;
mod transaction_guard;
mod transaction_state;

pub use redaction_handle::RedactionHandle;
pub use redaction_handle::RedactionHandleError;
pub use redaction_session::RedactionSession;
pub use redaction_session_output::RedactionSessionOutput;

pub(crate) use crate::domain::internal::DomainEntry;
