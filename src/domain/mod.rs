// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Runtime traits and borrowed views for domain-object redaction.

#[doc(hidden)]
pub mod internal;
mod redact;
mod redact_json_value;
mod redact_level_value;
mod redact_map_value;
mod redaction_writer;

pub use redact::Redact;
pub use redact_json_value::RedactJsonValue;
pub use redact_level_value::RedactLevelValue;
pub use redact_map_value::RedactMapValue;
pub use redaction_writer::RedactionEntries;
pub use redaction_writer::RedactionFields;
pub use redaction_writer::RedactionItems;
pub use redaction_writer::RedactionWriter;
