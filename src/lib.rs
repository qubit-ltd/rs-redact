// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! # Qubit Redact
//!
//! The pre-release redaction façades are intentionally not available.
//!
//! ```compile_fail
//! use qubit_redact::FieldSanitizer;
//! ```
//!
//! ```compile_fail
//! use qubit_redact::HttpBodySanitizer;
//! ```
//!
//! Provides immutable, policy-driven redaction for scalar fields, maps,
//! process diagnostics, and optionally HTTP data. Safe result types separate
//! redacted text from text that has also been escaped for logs.
//!
//! # Core values and maps
//!
//! ```
//! use std::collections::HashMap;
//! use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};
//!
//! let policy = RedactionPolicy::builder()
//!     .raise("tenant_secret", Sensitivity::Secret)
//!     .build()?;
//! let source = HashMap::from([
//!     ("tenant_secret".to_owned(), "raw".to_owned()),
//!     ("display_name".to_owned(), "Alice".to_owned()),
//! ]);
//! let redacted = Redactor::new(policy).redact_map(&source);
//! assert_eq!(redacted["tenant_secret"], "<redacted>");
//! assert_eq!(source["tenant_secret"], "raw");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! A process-wide default can be installed exactly once.
//! [`RedactionPolicy::builder`] starts from a snapshot of that default, and
//! existing policy snapshots never change.
//!
//! ```
//! use qubit_redact::{RedactionPolicy, Sensitivity};
//!
//! let application_default = RedactionPolicy::builder()
//!     .raise("tenant_secret", Sensitivity::Secret)
//!     .build()?;
//! RedactionPolicy::set_global_default(application_default)?;
//! let snapshot = RedactionPolicy::builder().build()?;
//! assert_eq!(snapshot.sensitivity_for("tenant_secret"), Some(Sensitivity::Secret));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! [`RedactedText`] is not directly displayable. Explicitly cross a plain-text
//! logging boundary with [`RedactedText::escape_for_log`].
//!
//! ```
//! use qubit_redact::Redactor;
//!
//! let safe = Redactor::default()
//!     .redact("message", "line one\nline two")
//!     .escape_for_log();
//! assert_eq!(safe.to_string(), "line one\\nline two");
//! ```
//!
//! # Process diagnostics
//!
//! ```
//! use std::ffi::OsStr;
//! use qubit_redact::{ArgvRedactor, EnvRedactor, argv::ArgvItem};
//!
//! let argv = [
//!     ArgvItem::plain(OsStr::new("client")),
//!     ArgvItem::plain(OsStr::new("--password")),
//!     ArgvItem::plain(OsStr::new("raw")),
//! ];
//! assert!(!ArgvRedactor::default()
//!     .redact_heuristically(argv)
//!     .to_string()
//!     .contains("raw"));
//! assert_eq!(
//!     EnvRedactor::default().redact_pair("PASSWORD", "raw").to_string(),
//!     "PASSWORD=<redacted>",
//! );
//! ```
//!
//! # HTTP bodies
//!
//! Enable this API with `qubit-redact = { version = "0.1", features = ["http"]
//! }`. `http::BodyCapture` makes completeness explicit, and the returned
//! `http::BodyRedaction` implements [`std::fmt::Display`] with bounded,
//! log-safe output.
//!
//! ```
//! # #[cfg(feature = "http")]
//! # {
//! use http::HeaderValue;
//! use qubit_redact::http::{BodyCapture, BodyRedaction, HttpRedactor};
//!
//! let content_type = HeaderValue::from_static("application/json");
//! let result: BodyRedaction = HttpRedactor::default().redact_body(
//!     BodyCapture::complete(br#"{"password":"raw","mode":"debug"}"#),
//!     Some(&content_type),
//! );
//! assert!(!format!("{result}").contains("raw"));
//! # }
//! ```

pub mod argv;
pub mod domain;
pub mod env;
#[cfg(feature = "http")]
pub mod http;
pub mod policy;
mod redactor;
pub mod text;

pub use argv::ArgvRedactor;
pub use domain::{
    Redact,
    RedactMapValue,
    RedactMapValueMut,
    RedactMut,
    RedactValue,
    RedactValueMut,
    Redacted,
    RedactedMap,
    RedactedValue,
};
pub use env::EnvRedactor;
pub use policy::{
    AllowRule,
    FieldNameMatching,
    GlobalDefaultAlreadySet,
    MaskPolicy,
    MaskingPolicy,
    PolicyError,
    RedactionPolicy,
    RedactionPolicyBuilder,
    SensitiveFieldPreset,
    SensitiveFieldRule,
    Sensitivity,
};
#[cfg(feature = "derive")]
pub use qubit_redact_derive::{
    Redact,
    RedactMut,
};
pub use redactor::Redactor;
pub use text::{
    LogSafeText,
    RedactedDebug,
    RedactedText,
    redacted_debug,
};
