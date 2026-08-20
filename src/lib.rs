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
//! formats. A [`RedactionSession`] is a reusable atomic transaction: aggregate
//! APIs append to one result, item APIs return [`RedactionHandle`]s, and only
//! [`RedactionSession::finish`] publishes text and resets the session.
//!
//! ```
//! use qubit_redact::Redactor;
//!
//! let mut session = Redactor::strict().session();
//! session.literal("password=").field("password", "raw-secret");
//! let output = session.finish();
//! assert!(!output.text().as_str().contains("raw-secret"));
//! ```
//!
//! # Safety boundary
//!
//! `literal` accepts only `&'static str` program literals. Dynamic text must
//! be passed to a redaction operation. Derived fields that lack
//! `#[redact(...)]`, or explicitly use `skip`, are intentionally unredacted;
//! every sensitive field must therefore be annotated.
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
//! Legacy domain-level rendering traits do not provide an alternate output
//! path. Domain values must be written through [`Redact`] and a
//! [`RedactionSession`].
//!
//! ```compile_fail
//! use qubit_redact::domain::RedactValue;
//! ```

extern crate self as qubit_redact;

pub mod domain;
mod facade;
pub mod formats;
mod json_feature_gate;
mod output;
pub mod policy;
pub(crate) mod runtime;
mod serde_feature_gate;

pub use domain::Redact;
pub use domain::RedactionWriter;
pub use facade::RedactedText;
pub use facade::RedactionOutput;
pub use facade::RedactionReason;
pub use facade::RedactionReasons;
pub use facade::RedactionSummary;
pub use facade::RedactionUsage;
pub use facade::Redactor;
pub use output::RedactionCompletion;
pub use policy::AllowRule;
pub use policy::FieldClassification;
pub use policy::FieldMatchKind;
pub use policy::FieldNameMatching;
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
pub use runtime::RedactionHandle;
pub use runtime::RedactionHandleError;
pub use runtime::RedactionSession;
pub use runtime::RedactionSessionOutput;
