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
mod batch_session;
mod bounded_field_writer;
mod field_rendering;
mod format_admission;
mod inspection_accumulator;
mod inspection_runtime;
mod inspection_session;
#[cfg(feature = "json")]
mod json_structure_admission;
#[cfg(any(feature = "json", feature = "http"))]
mod operation_byte_sink;
mod operation_sink;
mod redaction_budget;
mod redaction_handle;
mod render_runtime;
mod rendered_operation;
mod rendered_summary;
mod resettable_session;
mod runtime_core;
pub(crate) mod runtime_session;
mod structural_budget;
mod structural_entry;
mod summary_builder;
mod text_output_buffer;
mod text_session;
mod transaction_guard;
mod transaction_id;
mod transaction_phase;

pub(crate) use batch_publication::BatchPublication;
pub(crate) use batch_session::BatchSession;
pub(crate) use format_admission::admit_flat_format_item;
pub(crate) use format_admission::collect_flat_format_items;
pub(crate) use inspection_session::InspectionSession;
#[cfg(feature = "json")]
pub(crate) use json_structure_admission::JsonStructureAdmission;
#[cfg(any(feature = "json", feature = "http"))]
pub(crate) use operation_byte_sink::OperationByteSink;
pub(crate) use operation_sink::OperationSink;
pub use redaction_handle::RedactionHandle;
pub use redaction_handle::RedactionHandleError;
pub(crate) use rendered_operation::RenderedOperation;
pub(crate) use structural_budget::StructuralBudget;
pub(crate) use text_session::TextSession;
