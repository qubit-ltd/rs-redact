// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Private support for domain-object redaction.

mod nested;
#[cfg(any(feature = "serde", feature = "json"))]
mod redact_serialize;
#[cfg(feature = "json")]
pub use redact_serialize::RedactJsonSerialize;
#[cfg(any(feature = "serde", feature = "json"))]
pub use redact_serialize::RedactLevelSerialize;
#[cfg(any(feature = "serde", feature = "json"))]
pub use redact_serialize::RedactMapSerialize;
#[cfg(any(feature = "serde", feature = "json"))]
pub use redact_serialize::RedactSerialize;
#[cfg(any(feature = "serde", feature = "json"))]
pub use redact_serialize::RedactSerializeScope;
#[cfg(feature = "json")]
pub use redact_serialize::RedactedJsonSerializeRef;
#[cfg(any(feature = "serde", feature = "json"))]
pub use redact_serialize::RedactedLevelSerializeRef;
#[cfg(any(feature = "serde", feature = "json"))]
pub use redact_serialize::RedactedMapSerializeRef;
#[cfg(any(feature = "serde", feature = "json"))]
pub use redact_serialize::RedactedSerializeRef;
#[cfg(any(feature = "serde", feature = "json"))]
pub use redact_serialize::serialize_internally_tagged;
#[cfg(any(feature = "serde", feature = "json"))]
pub use redact_serialize::serialize_structured;
