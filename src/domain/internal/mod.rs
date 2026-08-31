// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Private support for domain-object redaction.

pub(super) mod bounded_capture;
pub(super) mod bounded_debug_writer;
#[cfg(any(feature = "serde", feature = "json"))]
mod bounded_display_writer;
#[cfg(any(feature = "serde", feature = "json"))]
mod internally_tagged_map;
#[cfg(any(feature = "serde", feature = "json"))]
mod internally_tagged_serializer;
mod keyed_policy;
mod nested;
#[cfg(feature = "json")]
mod redact_json_serialize;
#[cfg(any(feature = "serde", feature = "json"))]
mod redact_level_serialize;
#[cfg(any(feature = "serde", feature = "json"))]
mod redact_map_key_serialize;
#[cfg(any(feature = "serde", feature = "json"))]
mod redact_map_serialize;
#[cfg(any(feature = "serde", feature = "json"))]
mod redact_serialize;
#[cfg(any(feature = "serde", feature = "json"))]
mod redact_serialize_scope;
#[cfg(any(feature = "serde", feature = "json"))]
mod redact_value_serialize;
#[cfg(feature = "json")]
mod redacted_json_serialize_ref;
#[cfg(any(feature = "serde", feature = "json"))]
mod redacted_keyed_serialize_ref;
#[cfg(any(feature = "serde", feature = "json"))]
mod redacted_level_serialize_ref;
#[cfg(any(feature = "serde", feature = "json"))]
mod redacted_map_key_serialize_ref;
#[cfg(any(feature = "serde", feature = "json"))]
mod redacted_map_serialize_ref;
#[cfg(any(feature = "serde", feature = "json"))]
mod redacted_serialize_ref;
#[cfg(any(feature = "serde", feature = "json"))]
mod structured_serde_budget;
#[cfg(any(feature = "serde", feature = "json"))]
pub use internally_tagged_serializer::serialize_internally_tagged;
pub(crate) use keyed_policy::resolve_keyed_field;
#[cfg(feature = "json")]
pub use redact_json_serialize::RedactJsonSerialize;
#[cfg(any(feature = "serde", feature = "json"))]
pub use redact_level_serialize::RedactLevelSerialize;
#[cfg(any(feature = "serde", feature = "json"))]
pub use redact_map_key_serialize::RedactMapKeySerialize;
#[cfg(any(feature = "serde", feature = "json"))]
pub use redact_map_serialize::RedactMapSerialize;
#[cfg(any(feature = "serde", feature = "json"))]
pub use redact_serialize::RedactSerialize;
#[cfg(any(feature = "serde", feature = "json"))]
pub use redact_serialize_scope::RedactSerializeScope;
#[cfg(any(feature = "serde", feature = "json"))]
pub use redact_serialize_scope::serialize_structured;
#[cfg(feature = "json")]
pub use redacted_json_serialize_ref::RedactedJsonSerializeRef;
#[cfg(any(feature = "serde", feature = "json"))]
pub use redacted_keyed_serialize_ref::RedactedKeyedSerializeRef;
#[cfg(any(feature = "serde", feature = "json"))]
pub use redacted_level_serialize_ref::RedactedLevelSerializeRef;
#[cfg(any(feature = "serde", feature = "json"))]
pub use redacted_map_key_serialize_ref::RedactedMapKeySerializeRef;
#[cfg(any(feature = "serde", feature = "json"))]
pub use redacted_map_serialize_ref::RedactedMapSerializeRef;
#[cfg(any(feature = "serde", feature = "json"))]
pub use redacted_serialize_ref::RedactedSerializeRef;
