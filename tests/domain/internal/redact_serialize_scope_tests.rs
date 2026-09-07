// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Policy snapshot identity survives a forgotten guard and source replacement.

use std::mem::forget;
use std::thread;

#[cfg(feature = "derive")]
use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::domain::internal::RedactSerializeScope;
#[cfg(feature = "derive")]
use qubit_redact::domain::internal::RedactedProjectionRef;
use qubit_redact::domain::internal::current_policy;
#[cfg(feature = "derive")]
use serde_json::json;
#[cfg(feature = "derive")]
use serde_json::to_value;

/// Reusing a source address cannot restore a stale, weaker policy snapshot.
#[test]
fn test_forgotten_scope_does_not_override_replaced_policy() {
    thread::spawn(|| {
        let mut policy = RedactionPolicy::disabled();
        forget(RedactSerializeScope::new(&policy));
        policy = RedactionPolicy::standard();
        let _scope = RedactSerializeScope::new(&policy);
        assert_eq!(current_policy().as_deref(), Some(&policy));
    })
    .join()
    .expect("policy snapshot remains current");
}

/// A derived projection uses the replacement policy even at the same address.
#[cfg(feature = "derive")]
#[test]
fn test_forgotten_disabled_scope_cannot_expose_derived_secret() {
    #[derive(Redact)]
    struct Credential {
        #[redact(level = "secret")]
        token: String,
    }
    thread::spawn(|| {
        let value = Credential {
            token: "raw-secret".to_owned(),
        };
        let mut policy = RedactionPolicy::disabled();
        forget(RedactSerializeScope::new(&policy));
        policy = RedactionPolicy::standard();
        let output = to_value(RedactedProjectionRef::new(&value, &policy)).expect("redacted projection");
        assert_eq!(output, json!({"token": "<redacted>"}));
    })
    .join()
    .expect("replacement policy masks the source");
}
