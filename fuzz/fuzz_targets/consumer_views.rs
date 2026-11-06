// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Derived consumer projections under independent input, payload, and output
//! bounds.

#![cfg_attr(not(test), no_main)]

// Defines the composite payload used only by the fuzz entry point.
#[cfg(not(test))]
mod event;
// Defines the record shared by fuzz inputs and controlled oracle checks.
mod login;
// Defines the independent refusal budgets.
mod structural_limit;

#[cfg(not(test))]
use std::collections::BTreeMap;

#[cfg(not(test))]
use libfuzzer_sys::fuzz_target;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::RedactionReasons;
use qubit_redact::Redactor;
#[cfg(not(test))]
use serde_json::Value;
#[cfg(not(test))]
use serde_json::from_str;
#[cfg(not(test))]
use serde_json::json;
#[cfg(not(test))]
use serde_json::to_string;

#[cfg(not(test))]
use self::event::Event;
use self::login::Login;
use self::structural_limit::StructuralLimit;

const SECRET: &str = "consumer-view-secret-427b93";

/// Builds an otherwise standard policy with the selected budget set to zero.
///
/// # Parameters
///
/// * `limit` - Independent resource budget to exhaust for the refusal oracle.
///
/// # Returns
///
/// A fresh redactor owning the constrained policy.
#[must_use]
fn policy_with_structural_limit(limit: StructuralLimit) -> Redactor {
    let policy = RedactionPolicy::builder()
        .limits(|limits| match limit {
            StructuralLimit::Nodes => {
                limits.max_nodes(0);
            }
            StructuralLimit::Depth => {
                limits.max_depth(0);
            }
            StructuralLimit::Collection => {
                limits.max_collection_items(0);
            }
            StructuralLimit::Output => {
                limits.max_output_bytes(0);
            }
        })
        .expect("valid structural limit")
        .build()
        .expect("valid structural policy");
    Redactor::new(policy)
}

/// Checks that a fresh standard redactor still succeeds after a refusal.
fn assert_complete_standard_login() {
    let login = Login {
        label: "safe".into(),
        password: SECRET.into(),
    };
    let status = Redactor::standard()
        .to_json_with_status(&login)
        .expect("standard login encodes");
    assert!(status.is_complete());
    assert_eq!(status.reasons(), RedactionReasons::empty());
    assert!(!status.json().contains(SECRET));
}

/// Checks masking or one refusal path, followed by an independent recovery.
///
/// # Parameters
///
/// * `scenario` - Zero checks normal masking; one through four exhaust the
///   node, depth, collection, and output budgets, respectively.
///
/// # Panics
///
/// Panics if `scenario` exceeds four or an expected masking, refusal, or
/// independent recovery invariant fails.
fn check_controlled_status_case(scenario: u8) {
    let login = Login {
        label: "safe".into(),
        password: SECRET.into(),
    };

    match scenario {
        0 => {
            let masked = Redactor::standard()
                .to_json_with_status(&login)
                .expect("masked login encodes");
            assert!(masked.is_complete());
            assert_eq!(masked.reasons(), RedactionReasons::empty());
            assert!(masked.json().contains("<redacted>"));
            assert!(!masked.json().contains(SECRET));
        }
        1 => {
            let nodes = policy_with_structural_limit(StructuralLimit::Nodes)
                .to_json_with_status(&login)
                .expect("node refusal uses replacement");
            assert!(!nodes.is_complete());
            assert!(nodes.reasons().contains(RedactionReason::TraversalLimitReached));
            assert_eq!(nodes.json(), "\"<redacted>\"");
            assert!(!nodes.json().contains(SECRET));
            assert_complete_standard_login();
        }
        2 => {
            let depth = policy_with_structural_limit(StructuralLimit::Depth)
                .to_json_with_status(&login)
                .expect("depth refusal uses replacement");
            assert!(!depth.is_complete());
            assert!(depth.reasons().contains(RedactionReason::DepthLimitReached));
            assert_eq!(depth.json(), "\"<redacted>\"");
            assert!(!depth.json().contains(SECRET));
            assert_complete_standard_login();
        }
        3 => {
            let list = vec![Login {
                label: "safe".into(),
                password: SECRET.into(),
            }];
            let collection = policy_with_structural_limit(StructuralLimit::Collection)
                .to_json_with_status(&list)
                .expect("VecProjection collection refusal uses replacement");
            assert!(!collection.is_complete());
            assert!(collection.reasons().contains(RedactionReason::TraversalLimitReached));
            assert_eq!(collection.json(), "\"<redacted>\"");
            assert!(!collection.json().contains(SECRET));
            assert_complete_standard_login();
        }
        4 => {
            let output_error = policy_with_structural_limit(StructuralLimit::Output).to_json_with_status(&login);
            assert!(output_error.is_err());
            assert_complete_standard_login();
        }
        _ => unreachable!("scenario is bounded by the caller"),
    }
}

#[cfg(test)]
#[test]
fn test_controlled_status_oracles_cover_each_refusal_and_recovery() {
    for scenario in 0..=4 {
        check_controlled_status_case(scenario);
    }
}

#[cfg(not(test))]
fuzz_target!(|data: &[u8]| {
    let bounds = [0, 1, 2, 4, 8, 16, 64, 256];
    let select = |index| bounds[usize::from(data.get(index).copied().unwrap_or_default()) % bounds.len()];
    let input = select(0);
    let payload = select(1);
    let output = select(2);
    let nodes = select(3);
    let depth = select(4);
    let collection = select(5);
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
        body: json!({"password": SECRET, "mode": "visible"}),
    };
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits
                .max_input_bytes(input)
                .max_serde_payload_bytes(payload)
                .max_output_bytes(output)
                .max_nodes(nodes)
                .max_depth(depth)
                .max_collection_items(collection);
        })
        .expect("bounded draft")
        .build()
        .expect("bounded policy");
    let redactor = Redactor::new(policy);
    let view = redactor.redact_view(&event);
    let text = format!("{view}");
    assert!(text.len() <= output);
    assert!(!text.contains(SECRET));
    if let Ok(json) = to_string(&view) {
        assert!(!json.contains(SECRET));
    }
    let plain = redactor.to_json(&event);
    let reported = redactor.to_json_with_status(&event);
    assert_eq!(plain.is_ok(), reported.is_ok());
    if let (Ok(plain), Ok(reported)) = (plain, reported) {
        assert_eq!(plain, reported.json());
        assert!(reported.json().len() <= output);
        assert!(!reported.json().contains(SECRET));
        assert!(from_str::<Value>(reported.json()).is_ok());
        assert_eq!(reported.is_complete(), reported.reasons() == RedactionReasons::empty());
    }
    let scenario = data.get(6).copied().unwrap_or_default() % 5;
    check_controlled_status_case(scenario);
});
