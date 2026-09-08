// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg_attr(all(doctest, feature = "derive", feature = "http", feature = "serde"), doc = include_str!("../README.md"))]
#![cfg_attr(all(doctest, feature = "derive", feature = "http", feature = "serde"), doc = include_str!("../README.zh_CN.md"))]
#![cfg_attr(all(doctest, feature = "derive", feature = "http", feature = "serde"), doc = include_str!("../doc/user_guide.md"))]
#![cfg_attr(all(doctest, feature = "derive", feature = "http", feature = "serde"), doc = include_str!("../doc/user_guide.zh_CN.md"))]
//! # Qubit Redact
//!
//! Borrowed domain redaction for logs, errors, and structured diagnostics.
//! Choose [`Redactor::redact_view`] for lazy formatting/serialization, or
//! [`Redactor::redact_text`] for finalized text and a completeness summary.
//! With `json`, `Redactor::to_json` serializes a domain view directly.
//!
//! ```
//! use qubit_redact::Redactor;
//!
//! let output = Redactor::standard().redact_field("password", "raw-secret");
//! assert_eq!(output.text().as_str(), "<redacted>");
//! ```
//!
//! ## Domain and serialization capabilities
//!
//! `#[derive(Redact)]` implements [`Redact`]. `#[redact(debug)]` and
//! `#[redact(display)]` opt into ordinary diagnostic formatting. With `serde`,
//! the derive also generates structured redaction for views. Adding
//! `#[redact(serde)]` makes the source's ordinary Serialize implementation
//! redacted as well.
//!
//! [`RedactScalar`] supports one-field scalar newtypes without implementing
//! business Debug, Display, or Serialize. Explicit `level` annotations at the
//! use site determine sensitivity. Third-party values can select
//! `#[redact(level = "secret", display)]`.
//!
//! ## Policies and execution
//!
//! Views own immutable policy snapshots but borrow live source values. Every
//! use starts a new execution and budget. [`RedactedText`] is finalized and
//! does not run redaction again. [`DiagnosticRedactionBatch`] shares a budget
//! across related values; [`RedactedTextComposer`] builds one ordered message.
//!
//! Unmarked fields remain ordinary output. Explicit derive levels are final;
//! runtime field rules, floors, and strict mode do not override them. Disabled
//! policy deliberately restores source values. Generated ordinary formatting
//! and serialization read the application default at each call; explicit
//! views and redactors retain their captured policies.
//!
//! Text completion describes diagnostic completeness under the selected
//! policy. Ordinary logging can use `output.text()` directly; audit callers
//! can inspect summaries or reject incomplete text. This library does not
//! erase source memory or protect output that bypasses its entry points.
//!
//! See the [user guide](https://github.com/qubit-ltd/rs-redact/blob/main/doc/user_guide.md)
//! for complete setup, type/attribute tables, format integrations, and budgets.

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
#[cfg(test)]
mod tests;

pub use domain::Redact;
pub use domain::RedactScalar;
#[cfg(any(feature = "serde", feature = "json"))]
pub use domain::RedactSerialize;
pub use domain::RedactionWriter;
pub use facade::DebugDisplay;
pub use facade::DiagnosticRedactionBatch;
pub use facade::DiagnosticRedactionHandle;
pub use facade::DiagnosticRedactionOutput;
pub use facade::RedactedText;
pub use facade::RedactedTextComposer;
pub use facade::RedactedView;
pub use facade::RedactionInspection;
pub use facade::RedactionInspectionError;
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
#[cfg(feature = "derive")]
pub use qubit_redact_derive::RedactScalar;
pub(crate) use runtime::RedactionHandle;
pub(crate) use runtime::RedactionHandleError;
