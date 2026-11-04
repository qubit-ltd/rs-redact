// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Consumer view execution, collection scale, and independent budget
//! boundaries.

use std::hint::black_box;

use criterion::BenchmarkId;
use criterion::Criterion;
use criterion::criterion_group;
use criterion::criterion_main;
use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use serde_json::to_string;

#[derive(Redact)]
#[redact(serde)]
struct Login {
    user: String,
    #[redact(level = "secret")]
    password: String,
}

#[derive(Redact)]
#[redact(serde)]
struct Event {
    #[redact(nested)]
    logins: Vec<Login>,
}

#[derive(Redact)]
#[redact(serde)]
struct RecursiveNode {
    #[redact(nested)]
    child: Option<Box<RecursiveNode>>,
    #[redact(level = "secret")]
    secret: String,
}

fn recursive_node(depth: usize) -> RecursiveNode {
    RecursiveNode {
        child: (depth > 1).then(|| Box::new(recursive_node(depth - 1))),
        secret: "raw-secret".into(),
    }
}

/// Measures view construction separately from repeated executions of one view.
fn consumer_api(criterion: &mut Criterion) {
    let redactor = Redactor::standard();
    let mut group = criterion.benchmark_group("consumer-api");
    for count in [1, 8, 64] {
        let event = Event {
            logins: (0..count)
                .map(|_| Login {
                    user: "ada".into(),
                    password: "raw-secret".into(),
                })
                .collect(),
        };
        let view = redactor.redact_view(&event);
        assert!(to_string(&view).is_ok(), "normal view must serialize at scale {count}");
        assert!(
            redactor.to_json(&event).is_ok(),
            "normal JSON must encode at scale {count}"
        );
        group.bench_with_input(BenchmarkId::new("view-create", count), &event, |bencher, event| {
            bencher.iter(|| black_box(redactor.redact_view(black_box(event))));
        });
        group.bench_function(BenchmarkId::new("view-display", count), |bencher| {
            bencher.iter(|| black_box(format!("{}", black_box(&view))));
        });
        group.bench_function(BenchmarkId::new("view-serde", count), |bencher| {
            bencher.iter(|| black_box(to_string(black_box(&view))));
        });
        group.bench_with_input(BenchmarkId::new("redact-text", count), &event, |bencher, event| {
            bencher.iter(|| black_box(redactor.redact_text(black_box(event))));
        });
        group.bench_with_input(BenchmarkId::new("to-json", count), &event, |bencher, event| {
            bencher.iter(|| black_box(redactor.to_json(black_box(event))));
        });
        group.bench_with_input(
            BenchmarkId::new("to-json-with-status", count),
            &event,
            |bencher, event| {
                bencher.iter(|| black_box(redactor.to_json_with_status(black_box(event))));
            },
        );
    }
    group.finish();
}

/// Measures each boundary with all construction and expected-size work outside
/// timing.
fn budget_boundaries(criterion: &mut Criterion) {
    let value = Login {
        user: "abcd".into(),
        password: "raw-secret".into(),
    };
    let final_size = Redactor::standard().to_json(&value).expect("baseline JSON").len();
    let mut group = criterion.benchmark_group("consumer-budget");
    for (name, input, payload, output) in [
        ("input-below", 3, 128, 128),
        ("input-exact", 4, 128, 128),
        ("payload-below", 128, 13, 128),
        ("payload-exact", 128, 14, 128),
        ("encoded-below", 128, 128, final_size - 1),
        ("encoded-exact", 128, 128, final_size),
    ] {
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
        assert_eq!(
            redactor.to_json(&value).is_ok(),
            name.ends_with("exact"),
            "boundary {name}"
        );
        group.bench_function(name, |bencher| {
            bencher.iter(|| black_box(redactor.to_json(black_box(&value))))
        });
    }
    group.finish();
}

/// Measures policy snapshot work across small and nested successful values.
fn policy_snapshot(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("policy-snapshot");
    for rule_count in [0, 64, 512] {
        let policy = RedactionPolicy::builder()
            .fields(|fields| {
                for index in 0..rule_count {
                    fields.secret_sensitive(&format!("benchmark_secret_{index}"));
                }
            })
            .expect("valid benchmark rules")
            .limits(|limits| {
                limits
                    .max_depth(32)
                    .max_nodes(4096)
                    .max_collection_items(4096)
                    .max_input_bytes(1 << 20)
                    .max_serde_payload_bytes(1 << 20)
                    .max_output_bytes(1 << 20);
            })
            .expect("valid benchmark limits")
            .build()
            .expect("valid benchmark policy");
        let redactor = Redactor::new(policy);
        let equivalent_policy = redactor.policy().clone();
        let snapshot = std::sync::Arc::new(redactor.policy().clone());

        group.bench_function(
            BenchmarkId::new("policy-clone", format!("rules-{rule_count}")),
            |bencher| {
                bencher.iter(|| black_box(black_box(redactor.policy()).clone()));
            },
        );
        group.bench_function(
            BenchmarkId::new("policy-eq", format!("rules-{rule_count}")),
            |bencher| {
                bencher.iter(|| black_box(redactor.policy()) == black_box(&equivalent_policy));
            },
        );
        group.bench_function(
            BenchmarkId::new("snapshot-arc-clone", format!("rules-{rule_count}")),
            |bencher| {
                bencher.iter(|| black_box(std::sync::Arc::clone(black_box(&snapshot))));
            },
        );

        let small = Login {
            user: "ada".into(),
            password: "raw-secret".into(),
        };
        let small_view = redactor.redact_view(&small);
        assert!(to_string(&small_view).is_ok(), "small view must serialize");
        assert!(redactor.to_json(&small).is_ok(), "small value must serialize");
        assert!(
            redactor
                .to_json_with_status(&small)
                .expect("small value status")
                .is_complete()
        );

        for depth in [1, 4, 8] {
            let nested = recursive_node(depth);
            let nested_view = redactor.redact_view(&nested);
            assert!(to_string(&nested_view).is_ok(), "view must serialize at depth {depth}");
            assert!(
                redactor.to_json(&nested).is_ok(),
                "JSON must serialize at depth {depth}"
            );
            assert!(
                redactor
                    .to_json_with_status(&nested)
                    .expect("nested value status")
                    .is_complete(),
                "nested value must be complete at depth {depth}"
            );

            for (entry, operation) in [("view-serde", 0_u8), ("to-json", 1_u8), ("to-json-with-status", 2_u8)] {
                group.bench_function(
                    BenchmarkId::new(entry, format!("rules-{rule_count}-depth-{depth}")),
                    |bencher| {
                        bencher.iter(|| match operation {
                            0 => to_string(black_box(&nested_view)).map(|json| black_box(json).len()),
                            1 => redactor.to_json(black_box(&nested)).map(|json| black_box(json).len()),
                            _ => redactor
                                .to_json_with_status(black_box(&nested))
                                .map(|output| black_box(output.json()).len()),
                        });
                    },
                );
            }
        }

        for (entry, operation) in [("view-serde", 0_u8), ("to-json", 1_u8), ("to-json-with-status", 2_u8)] {
            group.bench_function(
                BenchmarkId::new(entry, format!("rules-{rule_count}-depth-1-small")),
                |bencher| {
                    bencher.iter(|| match operation {
                        0 => to_string(black_box(&small_view)).map(|json| black_box(json).len()),
                        1 => redactor.to_json(black_box(&small)).map(|json| black_box(json).len()),
                        _ => redactor
                            .to_json_with_status(black_box(&small))
                            .map(|output| black_box(output.json()).len()),
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, consumer_api, budget_boundaries, policy_snapshot);
criterion_main!(benches);
