// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Policy-aware redaction for parsed JSON values and JSON stored as text.

pub(crate) mod internal;

pub(crate) mod batch_redaction;
mod bounded_json_redaction;
pub(crate) mod inspection;
mod json_admission_error;
mod json_redaction_writer;
#[cfg(test)]
pub(crate) mod parse_counter;

pub(crate) use json_admission_error::JsonAdmissionError;
pub use json_redaction_writer::JsonRedactionWriter;
#[cfg(feature = "http")]
pub(crate) use json_redaction_writer::admit_json_text_structure_at_depth;
pub(crate) use json_redaction_writer::admit_json_text_value;
pub(crate) use json_redaction_writer::invalid_json_output;
pub(crate) use json_redaction_writer::redact_json_value_with_limit;
