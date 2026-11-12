// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Policy snapshot identity survives a forgotten guard and source replacement.

use std::mem::forget;
use std::panic::catch_unwind;
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

/// Releasing an outer scope must leave the live inner policy active.
#[test]
fn test_out_of_order_drop_keeps_inner_policy_until_inner_drop() {
    thread::spawn(|| {
        let outer_policy = RedactionPolicy::disabled();
        let inner_policy = RedactionPolicy::standard();
        let outer = RedactSerializeScope::new(&outer_policy);
        let inner = RedactSerializeScope::new(&inner_policy);

        drop(outer);
        assert_eq!(current_policy().as_deref(), Some(&inner_policy));

        drop(inner);
        assert!(current_policy().is_none());
    })
    .join()
    .expect("out-of-order scope cleanup preserves the active policy");
}

/// Releasing a middle scope leaves the newest live scope active and later
/// drains released frames when the stack tail is dropped.
#[test]
fn test_out_of_order_drop_drains_released_middle_frame() {
    thread::spawn(|| {
        let policy_a = RedactionPolicy::disabled();
        let policy_b = RedactionPolicy::standard();
        let policy_c = RedactionPolicy::standard()
            .to_builder()
            .limits(|limits| {
                limits.max_nodes(17);
            })
            .expect("custom limits should be valid")
            .build()
            .expect("custom policy should build");
        let scope_a = RedactSerializeScope::new(&policy_a);
        let scope_b = RedactSerializeScope::new(&policy_b);
        let scope_c = RedactSerializeScope::new(&policy_c);

        drop(scope_b);
        assert_eq!(current_policy().as_deref(), Some(&policy_c));

        let scope_d = RedactSerializeScope::new(&policy_b);
        assert_eq!(current_policy().as_deref(), Some(&policy_b));
        drop(scope_d);
        assert_eq!(current_policy().as_deref(), Some(&policy_c));

        drop(scope_c);
        assert_eq!(current_policy().as_deref(), Some(&policy_a));
        drop(scope_a);
        assert!(current_policy().is_none());
    })
    .join()
    .expect("released middle frames are drained in stack order");
}

/// Unwinding the last live child drains an already released outer frame.
#[test]
fn test_out_of_order_scope_drop_recovers_after_unwind() {
    thread::spawn(|| {
        let outer_policy = RedactionPolicy::disabled();
        let inner_policy = RedactionPolicy::standard();
        let result = catch_unwind(|| {
            let outer = RedactSerializeScope::new(&outer_policy);
            let _inner = RedactSerializeScope::new(&inner_policy);
            drop(outer);
            panic!("exercise scope cleanup during unwinding");
        });
        assert!(result.is_err());
        assert!(current_policy().is_none());
    })
    .join()
    .expect("unwinding releases the active scope and its released ancestor");
}

/// A forgotten child keeps an already released ancestor out of the active
/// policy slot until the thread exits, without restoring that ancestor.
#[test]
fn test_forgotten_child_does_not_restore_released_outer_policy() {
    thread::spawn(|| {
        let outer_policy = RedactionPolicy::disabled();
        let inner_policy = RedactionPolicy::standard();
        let outer = RedactSerializeScope::new(&outer_policy);
        let inner = RedactSerializeScope::new(&inner_policy);
        drop(outer);
        forget(inner);
        assert_eq!(current_policy().as_deref(), Some(&inner_policy));
    })
    .join()
    .expect("a forgotten child does not restore the released outer policy");
}
