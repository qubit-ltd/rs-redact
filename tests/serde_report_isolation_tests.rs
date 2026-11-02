// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg(all(feature = "derive", feature = "json"))]

use std::cell::Cell;
use std::rc::Rc;

use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::RedactionReasons;
use qubit_redact::Redactor;
use serde::Serialize;
use serde::Serializer;

#[derive(Redact)]
struct Record {
    #[redact(level = "secret")]
    password: String,
}

#[derive(Debug)]
struct PanickingSerialize;
impl Serialize for PanickingSerialize {
    fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        panic!("serializer panic")
    }
}

#[derive(Redact)]
struct PanicRecord {
    #[redact(unmarked)]
    value: PanickingSerialize,
}

#[derive(Redact)]
struct NestedValue {
    #[redact(level = "secret")]
    value: String,
}

#[derive(Debug)]
struct NestedCallback {
    redactor: Redactor,
    child_complete: Rc<Cell<bool>>,
    child_reasons: Rc<Cell<RedactionReasons>>,
}

impl Serialize for NestedCallback {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let child = NestedValue {
            value: "nested-secret".into(),
        };
        let output = self.redactor.to_json_with_status(&child).expect("nested JSON output");
        self.child_complete.set(output.is_complete());
        self.child_reasons.set(output.reasons());
        serializer.serialize_str(output.json())
    }
}

#[derive(Redact)]
struct NestedParent {
    #[redact(unmarked)]
    child: NestedCallback,
}

#[derive(Debug)]
struct SwallowingAdmission;

impl Serialize for SwallowingAdmission {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let _ = qubit_redact::domain::internal::admit_serialize_items::<S::Error>(1);
        let _ = qubit_redact::domain::internal::admit_serialize_items::<S::Error>(1);
        serializer.serialize_str("safe-after-rejection")
    }
}

#[derive(Redact)]
struct SwallowParent {
    #[redact(unmarked)]
    child: SwallowingAdmission,
}

#[derive(Debug)]
struct ErrorSerialize;

impl Serialize for ErrorSerialize {
    fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom("intentional serializer error"))
    }
}

#[derive(Redact)]
struct ErrorParent {
    #[redact(unmarked)]
    child: ErrorSerialize,
}

struct DistinctLedgerSource {
    nested_redactor: Redactor,
    nested_complete: Cell<bool>,
}

struct DistinctLedgerProjection;

impl qubit_redact::domain::internal::RedactSerializeSource for DistinctLedgerSource {
    type RedactedFields<'value> = DistinctLedgerProjection;

    fn redacted_fields<'value>(&'value self, _: &RedactionPolicy) -> Self::RedactedFields<'value> {
        let child = NestedValue {
            value: "other-ledger-secret".into(),
        };
        let output = self
            .nested_redactor
            .to_json_with_status(&child)
            .expect("separate-ledger nested output");
        self.nested_complete.set(output.is_complete());
        DistinctLedgerProjection
    }
}

impl Serialize for DistinctLedgerProjection {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_unit()
    }
}

#[test]
fn test_repeated_calls_and_errors_do_not_leak_reports() {
    let value = Record {
        password: "secret-value".into(),
    };
    let standard = Redactor::standard();
    assert!(standard.to_json_with_status(&value).unwrap().is_complete());
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(0);
        })
        .unwrap()
        .build()
        .unwrap();
    let limited = Redactor::new(policy);
    let output = limited.to_json_with_status(&value).unwrap();
    assert!(output.reasons().contains(RedactionReason::TraversalLimitReached));
    assert!(standard.to_json_with_status(&value).unwrap().is_complete());

    let result = std::panic::catch_unwind(|| {
        let _ = standard.to_json_with_status(&PanicRecord {
            value: PanickingSerialize,
        });
    });
    assert!(result.is_err());
    assert!(standard.to_json_with_status(&value).unwrap().is_complete());
}

#[test]
fn test_reports_are_thread_local() {
    let value = Record {
        password: "secret-value".into(),
    };
    let handles: Vec<_> = (0..4)
        .map(|index| {
            let value = Record {
                password: value.password.clone(),
            };
            std::thread::spawn(move || {
                let redactor = if index % 2 == 0 {
                    Redactor::standard()
                } else {
                    Redactor::new(
                        RedactionPolicy::builder()
                            .limits(|limits| {
                                limits.max_nodes(0);
                            })
                            .unwrap()
                            .build()
                            .unwrap(),
                    )
                };
                redactor.to_json_with_status(&value).unwrap().is_complete()
            })
        })
        .collect();
    for (index, handle) in handles.into_iter().enumerate() {
        assert_eq!(handle.join().unwrap(), index % 2 == 0);
    }
}

#[test]
fn test_nested_same_ledger_events_reach_both_active_reports() {
    let redactor = Redactor::new(
        RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_nodes(2);
            })
            .unwrap()
            .build()
            .unwrap(),
    );
    let child_complete = Rc::new(Cell::new(true));
    let child_reasons = Rc::new(Cell::new(RedactionReasons::empty()));
    let parent = NestedParent {
        child: NestedCallback {
            redactor: redactor.clone(),
            child_complete: Rc::clone(&child_complete),
            child_reasons: Rc::clone(&child_reasons),
        },
    };
    let output = redactor.to_json_with_status(&parent).unwrap();
    assert!(!child_complete.get());
    assert!(child_reasons.get().contains(RedactionReason::TraversalLimitReached));
    assert!(output.reasons().contains(RedactionReason::TraversalLimitReached));
}

#[test]
fn test_distinct_nested_ledger_does_not_pollute_parent() {
    let nested_redactor = Redactor::new(
        RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_nodes(0);
            })
            .unwrap()
            .build()
            .unwrap(),
    );
    let source = DistinctLedgerSource {
        nested_redactor,
        nested_complete: Cell::new(true),
    };
    let output = Redactor::standard().to_json_with_status(&source).unwrap();
    assert!(!source.nested_complete.get());
    assert!(output.is_complete());
}

#[test]
fn test_swallowed_repeated_admission_rejections_remain_observable() {
    let redactor = Redactor::new(
        RedactionPolicy::builder()
            .limits(|limits| {
                // The outer field consumes one item; the custom serializer's
                // two additional admissions are each rejected.
                limits.max_collection_items(1);
            })
            .unwrap()
            .build()
            .unwrap(),
    );
    let output = redactor
        .to_json_with_status(&SwallowParent {
            child: SwallowingAdmission,
        })
        .unwrap();
    assert_eq!(output.json(), r#"{"child":"safe-after-rejection"}"#);
    assert!(output.reasons().contains(RedactionReason::TraversalLimitReached));
}

#[test]
fn test_serializer_error_cleanup_restores_next_call() {
    let redactor = Redactor::standard();
    assert!(
        redactor
            .to_json_with_status(&ErrorParent { child: ErrorSerialize })
            .is_err()
    );
    let good = Record {
        password: "still-secret".into(),
    };
    assert!(redactor.to_json_with_status(&good).unwrap().is_complete());
}
// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
