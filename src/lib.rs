// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! # Qubit Sanitize
//!
//! Provides reusable sanitization utilities for logs, diagnostics, and
//! structured debug output.
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

#[cfg(feature = "core")]
pub mod adapter;
#[cfg(feature = "core")]
pub mod core;

#[cfg(feature = "core")]
pub use adapter::{
    ArgvSanitizer,
    EnvSanitizer,
};
#[cfg(feature = "web")]
pub use adapter::{
    FormUrlEncodedSanitizer,
    UrlSanitizer,
};
#[cfg(feature = "http")]
pub use adapter::{
    HttpBodySanitizer,
    HttpHeaderSanitizer,
    TextBodyPolicy,
};
#[cfg(feature = "core")]
pub use core::{
    DEFAULT_EXTRA_FIELDS,
    FieldSanitizePolicy,
    FieldSanitizer,
    MaskPolicies,
    MaskPolicy,
    NameMatchMode,
    SensitiveFieldPreset,
    SensitiveFields,
    SensitivityLevel,
    canonicalize_field_name,
};
