// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared execution-time accounting for bounded redaction operations.

mod batch_output_buffer;
mod bounded_field_writer;
mod item_range;
mod publication_buffer;
mod redaction_budget;
mod redaction_handle;
mod redaction_runtime;
mod redaction_session;
mod redaction_session_output;
mod rendered_operation;
mod summary_builder;
mod text_output_buffer;
mod transaction_guard;
mod transaction_phase;
mod transaction_state;

pub use redaction_handle::RedactionHandle;
pub use redaction_handle::RedactionHandleError;
pub use redaction_session::RedactionSession;
pub(crate) use redaction_session_output::BatchPublication;
pub(crate) use rendered_operation::RenderedOperation;

pub(crate) use crate::domain::internal::DomainEntry;
