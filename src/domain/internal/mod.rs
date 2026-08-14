// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Private support for domain-object redaction.

#[cfg(feature = "serde")]
mod internally_tagged_serializer;
mod mask_byte_limit;
mod mask_byte_limit_reset;
mod nested;
#[cfg(feature = "serde")]
mod redacted_serialize;

#[cfg(feature = "serde")]
pub use internally_tagged_serializer::serialize_internally_tagged;
pub(crate) use mask_byte_limit::debug_output_exhausted;
pub(crate) use mask_byte_limit::mark_debug_output_exhausted;
pub(crate) use mask_byte_limit::mask_byte_limit;
pub(crate) use mask_byte_limit::with_debug_output_tracking;
pub(crate) use mask_byte_limit::with_mask_byte_limit;
#[cfg(feature = "serde")]
pub use redacted_serialize::RedactedSerialize;
