// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! # Qubit Sanitize
//!
//! Provides reusable utilities for masking configured sensitive fields in
//! logs, diagnostics, and structured debug output.
//!
//! The core API sanitizes one `(field, value)` pair at a time and requires the
//! caller to choose a [`NameMatchMode`].
//!
//! ```
//! use qubit_sanitize::{
//!     FieldSanitizer,
//!     NameMatchMode,
//! };
//!
//! let sanitizer = FieldSanitizer::default();
//!
//! assert_eq!(
//!     sanitizer.sanitize_value("password", "secret", NameMatchMode::Exact),
//!     "<redacted>",
//! );
//! assert_eq!(
//!     sanitizer.sanitize_value("OPENAI_API_KEY", "abcdef", NameMatchMode::Exact),
//!     "abcdef",
//! );
//! assert_eq!(
//!     sanitizer.sanitize_value(
//!         "OPENAI_API_KEY",
//!         "abcdef",
//!         NameMatchMode::ExactOrSuffix,
//!     ),
//!     "****",
//! );
//! ```
//!
//! Adapter APIs apply the same explicit matching mode to structured inputs.
//! They only inspect formats and field names they explicitly model; callers
//! remain responsible for application-specific secrets and protocols.
//!
//! ```
//! # #[cfg(feature = "http")]
//! # fn main() {
//! use http::header::{
//!     AUTHORIZATION,
//!     HeaderValue,
//! };
//! use qubit_sanitize::{
//!     HttpHeaderSanitizer,
//!     NameMatchMode,
//! };
//!
//! let sanitizer = HttpHeaderSanitizer::default();
//! let value = HeaderValue::from_static("Bearer abcdef");
//!
//! assert_eq!(
//!     sanitizer.sanitize_value(&AUTHORIZATION, &value, NameMatchMode::ExactOrSuffix),
//!     "****",
//! );
//! # }
//! # #[cfg(not(feature = "http"))]
//! # fn main() {}
//! ```

pub mod adapter;
pub mod core;

pub use adapter::{
    ArgvSanitizer,
    EnvSanitizer,
};
#[cfg(feature = "http")]
pub use adapter::{
    BodyRedactionReason,
    BodySanitization,
    BodySanitizationStatus,
    BodySourceLength,
    HttpBodySanitizer,
    HttpHeaderSanitizer,
    TextBodyPolicy,
};
#[cfg(feature = "web")]
pub use adapter::{
    FormUrlEncodedSanitizer,
    UrlSanitizer,
};
pub use core::{
    DEFAULT_EXTRA_FIELDS,
    FieldSanitizePolicy,
    FieldSanitizer,
    MaskPolicies,
    MaskPolicy,
    NameMatchMode,
    RedactedDebug,
    SensitiveFieldPreset,
    SensitiveFields,
    SensitivityLevel,
    canonicalize_field_name,
    redacted_debug,
};
