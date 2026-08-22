// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Private support for domain-object redaction.

mod nested;
#[cfg(feature = "serde")]
mod redact_serialize;
#[cfg(feature = "serde")]
pub use redact_serialize::RedactSerialize;
