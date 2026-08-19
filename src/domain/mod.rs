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
#[cfg(feature = "serde")]
mod redact_map_serialize;
mod redact_map_value;
mod redact_map_value_mut;
mod redact_mut;
#[cfg(feature = "serde")]
mod redact_serialize;
mod redact_value;
mod redact_value_mut;
mod redacted_value;
mod redaction_writer;

pub use redact::Redact;
#[cfg(feature = "serde")]
#[doc(hidden)]
pub use redact_map_serialize::RedactMapSerialize;
pub use redact_map_value::RedactMapValue;
pub use redact_map_value_mut::RedactMapValueMut;
pub use redact_mut::RedactMut;
#[cfg(feature = "serde")]
#[doc(hidden)]
pub use redact_serialize::RedactSerialize;
pub use redact_value::RedactValue;
pub use redact_value_mut::RedactValueMut;
pub(crate) use redacted_value::RedactedValue;
pub use redaction_writer::RedactionFields;
pub use redaction_writer::RedactionWriter;
