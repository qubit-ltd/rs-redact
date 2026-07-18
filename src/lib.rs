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
//! Field sanitization is not log escaping: values whose field names are not
//! classified as sensitive may be returned unchanged, including control
//! characters. At untrusted text boundaries, callers should use structured
//! logging, [`escape_log_control_characters`], or adapter display helpers such
//! as [`ArgvSanitizer::sanitize_argv_display`] and
//! [`EnvSanitizer::sanitize_assignments_display`]. HTTP body
//! `BodySanitization::rendered` and `BodySanitization::into_rendered` escape
//! control characters; `BodySanitization::content` intentionally remains raw
//! sanitized content.
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

#[cfg(feature = "form")]
pub use adapter::FormUrlEncodedSanitizer;
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
    UnkeyedJsonValuePolicy,
};
#[cfg(feature = "web")]
pub use adapter::{
    UrlPathPolicy,
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
    escape_log_control_characters,
    redacted_debug,
};
