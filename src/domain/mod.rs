// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Runtime traits and borrowed views for domain-object redaction.

pub(crate) mod internal;
mod redact;
mod redact_map_value_mut;
mod redact_mut;
mod redact_value_mut;
mod redaction_writer;

pub use redact::Redact;
pub use redact_map_value_mut::RedactMapValueMut;
pub use redact_mut::RedactMut;
pub use redact_value_mut::RedactValueMut;
pub use redaction_writer::RedactionEntries;
pub use redaction_writer::RedactionFields;
pub use redaction_writer::RedactionItems;
pub use redaction_writer::RedactionWriter;
