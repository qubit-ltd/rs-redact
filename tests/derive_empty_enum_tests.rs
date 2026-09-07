// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Uninhabited domain enums retain their derived formatting and Serde
//! capabilities.

#![cfg(feature = "derive")]

use std::fmt::Debug;
use std::fmt::Display;

use qubit_redact::Redact;
#[cfg(feature = "serde")]
use qubit_redact::domain::internal::RedactSerializeSource;
#[cfg(feature = "serde")]
use serde::Serialize;

/// Empty enums are valid domain types even though no value can be constructed.
#[test]
fn test_empty_enum_derives_text_capabilities() {
    #[derive(Redact)]
    #[redact(debug, display)]
    enum Never {}
    fn requires_text<T: Redact + Debug + Display>() {}
    requires_text::<Never>();
}

/// Empty enums expose both borrowed projections and optional source
/// serialization.
#[cfg(feature = "serde")]
#[test]
fn test_empty_enum_derives_serde_capabilities() {
    #[derive(Redact)]
    #[redact(serde)]
    enum Never {}
    fn requires_serde<T: Serialize + RedactSerializeSource>()
    where
        for<'a> T::RedactedFields<'a>: Serialize,
    {
    }
    requires_serde::<Never>();
}
