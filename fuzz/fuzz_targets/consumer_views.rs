// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Derived consumer projections under independent input, payload, and output
//! bounds.

#![no_main]

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;

const SECRET: &str = "consumer-view-secret-427b93";

#[derive(Redact)]
#[redact(serde)]
struct Login {
    label: String,
    #[redact(level = "secret")]
    password: String,
}

#[derive(Redact)]
#[redact(serde)]
struct Event {
    #[redact(nested)]
    login: Login,
    #[redact(map)]
    attributes: BTreeMap<String, String>,
    #[redact(json)]
    body: serde_json::Value,
}

fuzz_target!(|data: &[u8]| {
    let bounds = [0, 1, 4, 8, 9, 10, 16, 32, 128, 4096];
    let select = |index| bounds[usize::from(data.get(index).copied().unwrap_or_default()) % bounds.len()];
    let input = select(0);
    let payload = select(1);
    let output = select(2);
    let label: String = data
        .iter()
        .skip(3)
        .take(128)
        .map(|byte| char::from(b'a' + byte % 26))
        .collect();
    let event = Event {
        login: Login {
            label,
            password: SECRET.into(),
        },
        attributes: BTreeMap::from([("password".into(), SECRET.into()), ("mode".into(), "visible".into())]),
        body: serde_json::json!({"password": SECRET, "mode": "visible"}),
    };
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits
                .max_input_bytes(input)
                .max_serde_payload_bytes(payload)
                .max_output_bytes(output);
        })
        .expect("bounded draft")
        .build()
        .expect("bounded policy");
    let redactor = Redactor::new(policy);
    let view = redactor.redact_view(&event);
    let text = format!("{view}");
    assert!(text.len() <= output);
    assert!(!text.contains(SECRET));
    if let Ok(json) = serde_json::to_string(&view) {
        assert!(!json.contains(SECRET));
    }
    if let Ok(json) = redactor.to_json(&event) {
        assert!(json.len() <= output);
        assert!(!json.contains(SECRET));
        assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());
    }
});
