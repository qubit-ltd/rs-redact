// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Private support for domain-object redaction.

mod domain_redaction_context;
#[cfg(feature = "serde")]
mod internally_tagged_serializer;
mod nested;
#[cfg(feature = "serde")]
mod redacted_serialize;

pub(crate) use domain_redaction_context::DomainEntry;
pub(crate) use domain_redaction_context::DomainRedactionContext;
#[cfg(feature = "serde")]
pub use internally_tagged_serializer::serialize_internally_tagged;
#[cfg(feature = "serde")]
pub use redacted_serialize::RedactedSerialize;
