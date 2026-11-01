// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg(all(feature = "derive", feature = "serde"))]

use std::collections::BTreeMap;

use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use serde::Serialize;

#[derive(Serialize)]
#[serde(tag = "kind")]
enum NativeEvent {
    Payload(()),
    Empty(NativeUnit),
    Record(NativeWrapper),
    Nested(NativeLayer),
}

#[derive(Serialize)]
struct NativeUnit;

#[derive(Serialize)]
struct NativeRecord {
    value: u8,
}

#[derive(Serialize)]
struct NativeWrapper(NativeRecord);

#[derive(Serialize)]
struct NativeLayer(NativeWrapper);

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
#[serde(tag = "kind")]
enum Event {
    Payload(()),
    Empty(#[redact(nested)] UnitPayload),
    Wrapped(WrappedMap),
    Record(#[redact(nested)] RecordWrapper),
    Nested(#[redact(nested)] RecordLayer),
}

#[derive(Debug, Redact)]
#[redact(crate = qubit_redact, serde)]
struct UnitPayload;

#[derive(Debug, Serialize)]
struct WrappedMap(BTreeMap<&'static str, u8>);

#[derive(Debug, Redact)]
#[redact(crate = qubit_redact, serde)]
struct RecordPayload {
    value: u8,
}

#[derive(Debug, Redact)]
#[redact(crate = qubit_redact, serde)]
struct RecordWrapper(#[redact(nested)] RecordPayload);

#[derive(Debug, Redact)]
#[redact(crate = qubit_redact, serde)]
struct RecordLayer(#[redact(nested)] RecordWrapper);

#[test]
fn test_internally_tagged_newtype_unit_matches_native_serde() {
    let expected = serde_json::to_string(&NativeEvent::Payload(())).unwrap();
    let value = Event::Payload(());
    assert_eq!(expected, r#"{"kind":"Payload"}"#);
    assert_eq!(serde_json::to_string(&value).unwrap(), expected);
    assert_eq!(
        serde_json::to_string(&Redactor::standard().redact_view(&value)).unwrap(),
        expected
    );
}

#[test]
fn test_internally_tagged_newtype_wrapper_forwards_map_payload() {
    let value = Event::Wrapped(WrappedMap(BTreeMap::from([("value", 7)])));
    let output = serde_json::to_value(Redactor::standard().redact_view(&value)).unwrap();
    assert_eq!(output["kind"], "Wrapped");
    assert_eq!(output["value"], 7);
}

#[test]
fn test_unit_struct_and_nested_struct_wrappers_match_native_serde() {
    let redactor = Redactor::standard();

    let native = serde_json::to_string(&NativeEvent::Empty(NativeUnit)).unwrap();
    let source = Event::Empty(UnitPayload);
    assert_eq!(serde_json::to_string(&source).unwrap(), native);
    assert_eq!(serde_json::to_string(&redactor.redact_view(&source)).unwrap(), native);

    let native = serde_json::to_string(&NativeEvent::Record(NativeWrapper(NativeRecord { value: 7 }))).unwrap();
    let source = Event::Record(RecordWrapper(RecordPayload { value: 7 }));
    assert_eq!(serde_json::to_string(&source).unwrap(), native);
    assert_eq!(serde_json::to_string(&redactor.redact_view(&source)).unwrap(), native);

    let native = serde_json::to_string(&NativeEvent::Nested(NativeLayer(NativeWrapper(NativeRecord {
        value: 9,
    }))))
    .unwrap();
    let source = Event::Nested(RecordLayer(RecordWrapper(RecordPayload { value: 9 })));
    assert_eq!(serde_json::to_string(&source).unwrap(), native);
    assert_eq!(serde_json::to_string(&redactor.redact_view(&source)).unwrap(), native);
}

#[test]
fn test_nested_internally_tagged_wrappers_obey_depth_and_node_limits() {
    for policy in [
        RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_depth(2);
            })
            .unwrap()
            .build()
            .unwrap(),
        RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_nodes(2);
            })
            .unwrap()
            .build()
            .unwrap(),
    ] {
        let value = Event::Nested(RecordLayer(RecordWrapper(RecordPayload { value: 9 })));
        assert!(serde_json::to_string(&Redactor::new(policy).redact_view(&value)).is_err());
    }
}
