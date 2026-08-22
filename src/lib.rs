// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg_attr(all(doctest, feature = "http", feature = "serde"), doc = include_str!("../README.md"))]
#![cfg_attr(all(doctest, feature = "http", feature = "serde"), doc = include_str!("../README.zh_CN.md"))]
#![cfg_attr(all(doctest, feature = "http", feature = "serde"), doc = include_str!("../doc/user_guide.md"))]
#![cfg_attr(all(doctest, feature = "http", feature = "serde"), doc = include_str!("../doc/user_guide.zh_CN.md"))]
//! # Qubit Redact
//!
//! Policy-driven, bounded redaction for fields, domain values, and diagnostic
//! formats. [`RedactedTextComposer`] builds one ordered text result, while
//! [`RedactionBatch`] builds independently resolvable results. Each object is
//! single-use and publishes only through its consuming `finish` method.
//!
//! ```
//! use qubit_redact::Redactor;
//!
//! let output = Redactor::strict()
//!     .text_composer()
//!     .literal("password=")
//!     .field("password", "raw-secret")
//!     .finish();
//! assert!(!output.text().as_str().contains("raw-secret"));
//! ```
//!
//! # Safety boundary
//!
//! `literal` accepts only `&'static str` program literals. Dynamic text must
//! be passed to a redaction operation. Derived fields that lack
//! `#[redact(...)]` are intentionally unredacted; fields that explicitly use
//! `skip` are neither accessed nor emitted. Every sensitive field must
//! therefore be annotated.
//!
//! Transaction summaries are observations produced exclusively by a completed
//! transaction; callers cannot fabricate one outside the runtime.
//!
//! ```compile_fail
//! use qubit_redact::RedactionSummary;
//!
//! let _ = RedactionSummary::complete();
//! ```
//!
//! The removed pre-0.5 transaction API cannot be imported as a public
//! compatibility API.
//!
//! ```compile_fail
//! use qubit_redact::RedactionSession;
//! ```
//!
//! ```compile_fail
//! use qubit_redact::RedactionSessionOutput;
//! ```
//!
//! ```compile_fail
//! use qubit_redact::RedactionOutput;
//! ```
//!
//! ```compile_fail
//! use qubit_redact::RedactionHandle;
//! ```
//!
//! ```compile_fail
//! use qubit_redact::RedactionHandleError;
//! ```
//!
//! ```compile_fail
//! use qubit_redact::Redactor;
//!
//! let _ = Redactor::strict().session();
//! ```
//!
//! Composer and batch APIs deliberately do not overlap, and both publication
//! methods consume their owner.
//!
//! ```compile_fail
//! use qubit_redact::Redactor;
//!
//! let composer = Redactor::strict().text_composer();
//! let _ = composer.finish();
//! let _ = composer.literal("cannot reuse a finished composer");
//! ```
//!
//! ```compile_fail
//! use qubit_redact::Redactor;
//!
//! let mut batch = Redactor::strict().batch();
//! batch.literal("batch has no aggregate text API");
//! ```
//!
//! ```compile_fail
//! use qubit_redact::Redactor;
//!
//! let mut batch = Redactor::strict().batch();
//! let _ = batch.redact_field("password", "raw-secret");
//! let _ = batch.finish();
//! let _ = batch.redact_field("password", "cannot reuse a finished batch");
//! ```
//!
//! ```compile_fail
//! use qubit_redact::Redactor;
//!
//! let composer = Redactor::strict().text_composer();
//! let _ = composer.redact_field("password", "batch methods are unavailable");
//! ```
//!
//! ```compile_fail
//! use qubit_redact::Redactor;
//!
//! let mut batch = Redactor::strict().batch();
//! let handle = batch.redact_field("password", "raw-secret");
//! let output = batch.finish();
//! let _ = output.text();
//! let _ = handle.to_string();
//! ```
//!
//! The domain-level rendering traits do not provide an alternate output path.
//! Domain values must be written through [`Redact`] and a
//! [`RedactedTextComposer`] or [`RedactionBatch`].
//!
//! ```compile_fail
//! use qubit_redact::policy::RedactionPolicy;
//! ```

extern crate self as qubit_redact;

#[cfg(feature = "derive")]
pub use qubit_redact_derive::Redact;

#[doc(hidden)]
pub mod domain;
mod facade;
pub mod formats;
mod json_feature_gate;
mod output;
mod policy;
pub(crate) mod runtime;
mod serde_feature_gate;

pub use domain::Redact;
#[doc(hidden)]
pub use domain::RedactJsonValue;
#[doc(hidden)]
pub use domain::RedactLevelValue;
#[doc(hidden)]
pub use domain::RedactMapValue;
pub use domain::RedactionEntries;
pub use domain::RedactionFields;
pub use domain::RedactionItems;
pub use domain::RedactionWriter;
pub use facade::RedactedText;
pub use facade::RedactedTextComposer;
pub use facade::RedactionBatch;
pub use facade::RedactionBatchHandle;
pub use facade::RedactionBatchHandleError;
pub use facade::RedactionBatchOutput;
pub use facade::RedactionInspection;
pub use facade::RedactionInspectionError;
pub use facade::RedactionInspectionResult;
pub use facade::RedactionReason;
pub use facade::RedactionReasons;
pub use facade::RedactionSummary;
pub use facade::RedactionTextOutput;
pub use facade::RedactionUsage;
pub use facade::Redactor;
pub use output::RedactionCompletion;
pub use policy::AllowRule;
pub use policy::FieldClassification;
pub use policy::FieldMatchKind;
pub use policy::FieldNameMatching;
pub use policy::FieldsBuilder;
#[cfg(feature = "http")]
pub use policy::HttpContextBuilderView;
#[cfg(feature = "http")]
pub use policy::HttpPolicyBuilderView;
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
pub use policy::SensitiveFieldPreset;
pub use policy::SensitiveFieldRule;
pub use policy::Sensitivity;
#[cfg(feature = "json")]
pub use policy::UnkeyedJsonValuePolicy;
pub use policy::UnknownFieldPolicy;
#[cfg(feature = "uri")]
pub use policy::UriPolicyBuilderView;
pub(crate) use runtime::RedactionHandle;
pub(crate) use runtime::RedactionHandleError;
pub(crate) use runtime::RedactionSession;
