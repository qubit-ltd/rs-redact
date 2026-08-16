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
//! snapshots never change. Before an application installs a global policy,
//! `RedactionPolicy::global()` and `RedactionPolicy::default()` return the
//! fixed standard policy without preventing later installation.
//! This fallback supports dependency construction during application assembly;
//! it is not runtime reconfiguration. The executable, never a library, owns the
//! single installation and should complete it before starting concurrent work.
//! Anything created earlier keeps its standard-policy snapshot. Construct
//! policy-sensitive objects afterward or inject the application policy.
//! The standard/default policy is only the library's deterministic baseline;
//! it is not a claim that every application's fields are safe to pass through.
//! The host application is responsible for installing its complete redaction
//! policy once, or for injecting a stricter policy at each boundary whose
//! requirements exceed that baseline. Downstream callers must not treat a
//! default snapshot as an application-specific policy declaration.
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
//! ```
//! use std::collections::HashMap;
//! use qubit_redact::domain::Redact as _;
//! use qubit_redact::{RedactionPolicy, Sensitivity};
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
//! ```
//! use qubit_redact::domain::{Redact as _, RedactMut as _};
//! use qubit_redact_derive::Redact;
//!
//! #[derive(Clone, Redact)]
//! struct Secret {
//!     #[redact(level = "secret")]
//!     value: String,
//! }
//!
//! #[derive(Clone, Redact)]
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
//! derive crate, `#[redact(serde)]` makes direct serialization of the original
//! type use its redacted representation. [`domain::Redacted`] also supports
//! policy-aware serialization and intentionally does not implement
//! `Deserialize`.
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # #[cfg(feature = "serde")]
//! # {
//! use qubit_redact::domain::Redact as _;
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
//! let json = serde_json::to_string(&value)?;
//! assert!(!json.contains("raw-token"));
//! assert!(!json.contains("internal_note"));
//! assert!(!format!("{value:?}").contains("raw-token"));
//! assert!(!format!("{value}").contains("raw-token"));
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! `debug` and `display` are opt-in implementations on the original type and
//! use the process-wide default policy. Plain fields remain ordinary `Debug`
//! values. Redacted `Debug` and `Display` output use the policy's diagnostic
//! output budget by default. Use `with_output_limit()` to select a different
//! explicit limit. Do not request an
//! implementation already supplied by the type, such as combining
//! `#[derive(Debug)]` with `#[redact(debug)]`.
//!
//! Derives support named, tuple, and unit structs, plus enums with named,
//! tuple, and unit variants. With `#[redact(serde)]`, redacted serialization
//! supports Serde's external, internal, adjacent, and untagged enum
//! representations through a structure-preserving attribute allowlist.
//!
//! ```
//! use qubit_redact::domain::Redact as _;
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
//! use qubit_redact::argv::ArgvItem;
//! use qubit_redact::Redactor;
//!
//! let argv = [
//!     ArgvItem::plain(OsStr::new("client")),
//!     ArgvItem::plain(OsStr::new("--password")),
//!     ArgvItem::plain(OsStr::new("raw")),
//! ];
//! let redactor = Redactor::strict();
//! let mut session = redactor.session();
//! assert!(!session
//!     .argv()
//!     .redact_heuristically(argv)
//!     .to_string()
//!     .contains("raw"));
//! assert_eq!(
//!     session.env().redact_pair("PASSWORD", "raw").to_string(),
//!     "PASSWORD=<redacted>",
//! );
//! ```
//!
//! # JSON values
//!
//! With the `json` feature, `RedactedJson`, `RedactedJsonText`, and
//! `redact_json_text_in_place` share the `JsonDepthLimit` stored in their
//! immutable [`RedactionPolicy`] snapshot. The default maximum depth is 128;
//! an over-depth object or array is replaced with the policy's opaque Secret
//! mask without visiting its descendants.
//!
//! JSON text can share one diagnostic budget with other adapters through the
//! `RedactionSession::json` method when the `json` feature is enabled:
//!
//! ```
//! # fn main() {
//! # #[cfg(feature = "json")]
//! # {
//! use qubit_redact::Redactor;
//!
//! let redactor = Redactor::strict();
//! let mut session = redactor.session();
//! let safe = session.json().redact_text(r#"{"token":"raw-token"}"#);
//! assert!(!safe.to_string().contains("raw-token"));
//! # }
//! # }
//! ```
//!
//! # HTTP bodies
//!
//! Enable this API with `qubit-redact = { version = "0.5", features = ["http"]
//! }`. `http::BodyCapture` makes completeness explicit, and the returned
//! `http::BodyRedaction` implements [`std::fmt::Display`] with bounded,
//! log-safe output.
//!
//! ```
//! # fn main() {
//! # #[cfg(feature = "http")]
//! # {
//! use http::HeaderValue;
//! use qubit_redact::http::{BodyCapture, BodyRedaction, HttpRedactor};
//!
//! let content_type = HeaderValue::from_static("application/json");
//! let redactor = HttpRedactor::default();
//! let mut session = redactor.session();
//! let result: BodyRedaction = session.http().redact_body(
//!     BodyCapture::complete(br#"{"password":"raw","mode":"debug"}"#),
//!     Some(&content_type),
//! );
//! assert!(!format!("{result}").contains("raw"));
//! # }
//! # }
//! ```

//!
//! URI diagnostics use the same session model when the `uri` feature is
//! enabled:
//!
//! ```
//! # fn main() {
//! # #[cfg(feature = "uri")]
//! # {
//! use qubit_redact::uri::UriRedactor;
//!
//! let redactor = UriRedactor::default();
//! let mut session = redactor.session();
//! let safe = session.uri().redact_uri_str("https://example.test/path");
//! assert!(safe.log_safe_text().as_str().contains("example.test"));
//! # }
//! # }
//! ```

extern crate self as qubit_redact;

pub mod argv;
pub mod config;
pub mod domain;
pub mod env;
pub mod facade;
mod field_redaction;
#[cfg(feature = "http")]
pub mod http;
mod install_global_policy_error;
#[cfg(feature = "json")]
pub mod json;
mod json_feature_gate;
mod pass_through_reason;
pub mod policy;
pub(crate) mod runtime;
pub mod output;
pub mod formats;
#[cfg(feature = "serde")]
#[doc(hidden)]
pub mod __private;
mod redactor;
mod serde_feature_gate;
pub mod text;
#[cfg(feature = "uri")]
pub mod uri;

pub use field_redaction::FieldRedaction;
pub use field_redaction::PassThroughReason;
pub use facade::RedactionEvent;
pub use install_global_policy_error::InstallGlobalPolicyError;
pub use policy::AllowRule;
pub use policy::DiagnosticBudgetError;
pub use policy::DomainRedactionLimitsBuilder;
pub use policy::FieldClassification;
pub use policy::FieldMatchKind;
pub use policy::FieldNameMatching;
pub use policy::InputOutputLimit;
pub use policy::InputOutputLimitBuilder;
#[cfg(feature = "json")]
pub use policy::JsonDepthLimit;
#[cfg(feature = "json")]
pub use policy::JsonDepthLimitBuilder;
#[cfg(feature = "json")]
pub use policy::JsonDepthLimitError;
pub use policy::MaskPolicy;
pub use policy::MaskingPolicy;
pub use policy::MaskingPolicyBuilder;
pub use policy::PolicyError;
pub use policy::PolicyLocation;
pub use policy::RedactionFloor;
pub use policy::RedactionFloorBuilder;
pub use policy::RedactionLimits;
pub use policy::RedactionLimitsBuilder;
pub use policy::RedactionPolicy;
pub use policy::RedactionPolicyBuilder;
pub use policy::RedactionRules;
pub use policy::RedactionSession;
pub use policy::SensitiveFieldPreset;
pub use policy::SensitiveFieldRule;
pub use policy::Sensitivity;
#[cfg(feature = "json")]
pub use policy::UnkeyedJsonValuePolicy;
pub use policy::UnknownFieldPolicy;
pub use redactor::Redactor;
pub use text::BoundedLogSafeDisplay;
pub use text::DiagnosticLogBuilder;
pub use text::LogOutputLimit;
pub use text::LogOutputLimitBuilder;
pub use text::LogOutputLimitError;
pub use text::LogSafeText;
pub use text::RedactedDebug;
pub use text::RedactedText;
pub use text::RedactionCompletion;
pub use text::redacted_debug;
