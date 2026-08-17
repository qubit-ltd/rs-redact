// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Runtime traits and borrowed views for domain-object redaction.

mod bounded_redacted_display;
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
mod redacted;
mod redacted_keyed_map;
mod redacted_keyed_value;
mod redacted_map;
mod redacted_value;
mod redaction_writer;

pub use bounded_redacted_display::BoundedRedactedDisplay;
pub use redact::DomainTruncated;
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
pub use redacted::Redacted;
pub use redacted::RedactedResult;
pub use redacted_keyed_map::RedactedKeyedMap;
pub use redacted_keyed_map::RedactedKeyedMapResult;
pub use redacted_keyed_value::RedactedKeyedResult;
pub use redacted_keyed_value::RedactedKeyedValue;
pub use redacted_map::RedactedMap;
pub use redacted_map::RedactedMapResult;
pub use redacted_value::RedactedValue;
pub use redaction_writer::RedactionFields;
pub use redaction_writer::RedactionWriter;
