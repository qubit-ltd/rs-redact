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

pub mod argv;
pub mod env;
#[cfg(feature = "http")]
pub mod http;
pub mod policy;
mod redactor;
pub mod text;

pub use argv::ArgvRedactor;
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
pub use redactor::Redactor;
pub use text::{
    LogSafeText,
    RedactedDebug,
    RedactedText,
    redacted_debug,
};
