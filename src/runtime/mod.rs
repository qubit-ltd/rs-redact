// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared execution-time accounting for bounded redaction operations.

mod batch_output_buffer;
mod batch_publication;
mod bounded_field_writer;
mod inspection_accumulator;
#[cfg(any(feature = "json", feature = "http"))]
mod operation_byte_sink;
mod operation_sink;
mod publication_buffer;
mod redaction_budget;
mod redaction_handle;
mod redaction_runtime;
mod redaction_session;
mod rendered_operation;
mod structural_budget;
mod structural_entry;
mod summary_builder;
mod text_output_buffer;
mod transaction_guard;
mod transaction_phase;
mod transaction_state;

pub(crate) use batch_publication::BatchPublication;
#[cfg(any(feature = "json", feature = "http"))]
pub(crate) use operation_byte_sink::OperationByteSink;
pub(crate) use operation_sink::OperationSink;
pub use redaction_handle::RedactionHandle;
pub use redaction_handle::RedactionHandleError;
pub use redaction_session::RedactionSession;
pub(crate) use rendered_operation::RenderedOperation;
pub(crate) use structural_budget::StructuralBudget;
