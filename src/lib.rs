// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg_attr(
    all(doctest, feature = "http", feature = "serde"),
    doc = include_str!("../README.md")
)]
#![cfg_attr(
    all(doctest, feature = "http", feature = "serde"),
    doc = include_str!("../README.zh_CN.md")
)]
#![cfg_attr(
    all(doctest, feature = "http", feature = "serde"),
    doc = include_str!("../doc/user_guide.md")
)]
#![cfg_attr(
    all(doctest, feature = "http", feature = "serde"),
    doc = include_str!("../doc/user_guide.zh_CN.md")
)]
//! # Qubit Redact
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
//! let mut builder = RedactionPolicy::builder();
//! builder
//!     .fields()
//!     .raise("tenant_secret", Sensitivity::Secret)?;
//! let policy = builder.build()?;
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
//! An application can install one process-wide [`RedactionPolicy`] during
//! assembly or initialization. Builders are deterministic and never read
//! process-wide state; use `RedactionPolicy::default().to_builder()` when an
//! explicit extension of the installed snapshot is needed. Existing policy
//! snapshots never change. The first call to `RedactionPolicy::global()` or
//! `RedactionPolicy::default()` freezes the standard snapshot if no global
//! policy has been installed yet.
//!
//! ```
//! use qubit_redact::{RedactionPolicy, Sensitivity};
//!
//! let mut builder = RedactionPolicy::builder();
//! builder
//!     .fields()
//!     .raise("tenant_secret", Sensitivity::Secret)?;
//! let application_default = builder.build()?;
//! RedactionPolicy::install_global(application_default)?;
//! let snapshot = RedactionPolicy::default();
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
//!     .redact_field("message", "line one\nline two")
//!     .escape_for_log();
//! assert_eq!(safe.to_string(), "line one\\nline two");
//! ```
//!
//! # Domain objects
//!
//! Add the companion `qubit-redact-derive` crate to annotate fields explicitly.
//! Plain fields are never recursively redacted, `nested` is the recursion
//! boundary, `map` classifies each value by its runtime key, and `skip` omits a
//! field only from the redacted representation.
//!
//! ```ignore
//! use std::collections::HashMap;
//! use qubit_redact::{Redact as _, RedactionPolicy, Sensitivity};
//! use qubit_redact_derive::Redact;
//!
//! #[derive(Redact)]
//! struct Account {
//!     id: u64,
//!     #[redact(level = "secret")]
//!     password: String,
//!     #[redact(map)]
//!     metadata: HashMap<String, String>,
//! }
//!
//! let mut builder = RedactionPolicy::builder();
//! builder.fields().raise("api_key", Sensitivity::Secret)?;
//! let policy = builder.build()?;
//! let account = Account {
//!     id: 1,
//!     password: "raw-password".to_owned(),
//!     metadata: HashMap::from([
//!         ("api_key".to_owned(), "raw-key".to_owned()),
//!     ]),
//! };
//! let output = format!("{:?}", account.redacted_with(&policy));
//! assert!(!output.contains("raw-password"));
//! assert!(!output.contains("raw-key"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! `RedactMut` is an explicit logical in-place redaction contract. The skipped
//! field below remains unchanged, while `nested` uses the same policy for the
//! child. It does not zeroize released allocations or affect aliases, existing
//! copies, or borrowed backing data. Clone-based `to_redacted` temporarily
//! retains a second raw copy. Use a separately designed zeroization strategy
//! when memory erasure is required.
//!
//! ```ignore
//! use qubit_redact::{Redact as _, RedactMut as _};
//! use qubit_redact_derive::{Redact, RedactMut};
//!
//! #[derive(Clone, Redact, RedactMut)]
//! struct Secret {
//!     #[redact(level = "secret")]
//!     value: String,
//! }
//!
//! #[derive(Clone, Redact, RedactMut)]
//! struct Envelope {
//!     #[redact(nested)]
//!     secret: Secret,
//!     #[redact(skip)]
//!     internal_note: String,
//! }
//!
//! let mut envelope = Envelope {
//!     secret: Secret { value: "raw".to_owned() },
//!     internal_note: "unchanged".to_owned(),
//! };
//! envelope.redact_in_place();
//! assert_eq!(envelope.secret.value, "<redacted>");
//! assert_eq!(envelope.internal_note, "unchanged");
//! ```
//!
//! With the `serde` feature, a direct `serde` dependency, and the companion
//! derive crate, `#[redact(serde)]` opts the redacted view into serialization.
//! [`Redacted`] intentionally does not implement `Deserialize`.
//!
//! ```ignore
//! # #[cfg(feature = "serde")]
//! # {
//! use qubit_redact::Redact as _;
//! use qubit_redact_derive::Redact;
//!
//! #[derive(Redact)]
//! #[redact(debug, display, serde)]
//! struct Credentials {
//!     #[redact(level = "secret")]
//!     token: String,
//!     #[redact(skip)]
//!     internal_note: String,
//! }
//!
//! let value = Credentials {
//!     token: "raw-token".to_owned(),
//!     internal_note: "not serialized".to_owned(),
//! };
//! let json = serde_json::to_string(&value.redacted())?;
//! assert!(!json.contains("raw-token"));
//! assert!(!json.contains("internal_note"));
//! assert!(!format!("{value:?}").contains("raw-token"));
//! assert!(!format!("{value}").contains("raw-token"));
//! # }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! `debug` and `display` are opt-in implementations on the original type and
//! use the process-wide default policy. Plain fields remain ordinary `Debug`
//! values. Redacted `Debug` output uses the policy's diagnostic output budget
//! by default; call `with_policy_output_limit()` when `Display` output must be
//! bounded by an explicit policy limit as well. Do not request an
//! implementation already supplied by the type, such as combining
//! `#[derive(Debug)]` with `#[redact(debug)]`.
//!
//! Derives support named, tuple, and unit structs, plus enums with named,
//! tuple, and unit variants. With `#[redact(serde)]`, redacted serialization
//! supports Serde's external, internal, adjacent, and untagged enum
//! representations through a structure-preserving attribute allowlist.
//!
//! ```ignore
//! use qubit_redact::Redact as _;
//! use qubit_redact_derive::Redact;
//!
//! #[derive(Redact)]
//! struct Token(#[redact(level = "secret")] String);
//!
//! #[derive(Redact)]
//! enum Event {
//!     Credential(#[redact(level = "secret")] String),
//!     Ready,
//! }
//!
//! assert_eq!(
//!     format!("{:?}", Token("raw".into()).redacted()),
//!     "Token(\"<redacted>\")",
//! );
//! assert_eq!(
//!     format!("{:?}", Event::Credential("raw".into()).redacted()),
//!     "Credential(\"<redacted>\")",
//! );
//! assert_eq!(format!("{:?}", Event::Ready.redacted()), "Ready");
//! ```
//!
//! `redacted()` snapshots the process default; `redacted_with` snapshots an
//! explicit policy, which every nested and map field reuses. Field-specific
//! map policies are not supported in the first version; use a domain newtype
//! plus `nested` for a separate policy boundary.
//!
//! # Process diagnostics
//!
//! Process adapters use the [`InputOutputLimit`] in their [`RedactionPolicy`]
//! snapshot. They stop before inspecting argv or environment input beyond the
//! input limit and truncate their final log-safe list at the output limit.
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
//! # JSON values
//!
//! With the `json` feature, `RedactedJson`, `RedactedJsonText`, and
//! `redact_json_text_in_place` share the `JsonDepthBudget` stored in their
//! immutable [`RedactionPolicy`] snapshot. The default maximum depth is 128;
//! an over-depth object or array is replaced with the policy's opaque Secret
//! mask without visiting its descendants.
//!
//! # HTTP bodies
//!
//! Enable this API with `qubit-redact = { version = "0.6", features = ["http"]
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

extern crate self as qubit_redact;

pub mod argv;
pub mod domain;
pub mod env;
mod field_redaction;
#[cfg(feature = "http")]
pub mod http;
mod install_global_policy_error;
#[cfg(feature = "json")]
pub mod json;
mod json_feature_gate;
mod pass_through_reason;
pub mod policy;
#[cfg(feature = "serde")]
mod private;
mod redactor;
mod serde_feature_gate;
pub mod text;
#[cfg(feature = "uri")]
pub mod uri;

pub use argv::ArgvRedactor;
pub use domain::{
    BoundedRedactedDisplay,
    Redact,
    RedactMapValue,
    RedactMapValueMut,
    RedactMut,
    RedactValue,
    RedactValueMut,
    Redacted,
    RedactedKeyedMap,
    RedactedKeyedMapSession,
    RedactedKeyedValue,
    RedactedKeyedValueSession,
    RedactedMap,
    RedactedMapSession,
    RedactedSessionView,
    RedactedValue,
};
pub use env::EnvRedactor;
pub use field_redaction::{
    FieldRedaction,
    PassThroughReason,
};
pub use install_global_policy_error::InstallGlobalPolicyError;
#[cfg(feature = "json")]
pub use json::{
    RedactedJson,
    RedactedJsonSession,
    RedactedJsonText,
    RedactedJsonTextSession,
    redact_json_text_in_place,
};
pub use policy::{
    AllowRule,
    DiagnosticBudget,
    DiagnosticBudgetError,
    DiagnosticInputBudget,
    FieldClassification,
    FieldMatchKind,
    FieldNameMatching,
    InputOutputLimit,
    MaskPolicy,
    MaskingPolicy,
    PolicyError,
    PolicyLocation,
    RedactionFloor,
    RedactionFloorBuilder,
    RedactionLimits,
    RedactionPolicy,
    RedactionPolicyBuilder,
    RedactionRules,
    RedactionSession,
    RedactionSessionKind,
    SensitiveFieldPreset,
    SensitiveFieldRule,
    Sensitivity,
    UnknownFieldPolicy,
};
#[cfg(feature = "json")]
pub use policy::{
    JsonDepthBudget,
    JsonDepthBudgetError,
    UnkeyedJsonValuePolicy,
};
pub use redactor::Redactor;
pub use text::{
    BoundedLogSafeDisplay,
    DiagnosticLogBuilder,
    DiagnosticWriteStatus,
    LogOutputLimit,
    LogOutputLimitError,
    LogSafeText,
    RedactedDebug,
    RedactedText,
    redacted_debug,
};
#[cfg(feature = "uri")]
pub use uri::{
    UriComponent,
    UriFragmentPolicy,
    UriInspection,
    UriPathPolicy,
    UriPolicy,
    UriRedaction,
    UriRedactionReason,
    UriRedactionStatus,
    UriRedactor,
};

#[cfg(feature = "serde")]
#[doc(hidden)]
pub use private::__private;
