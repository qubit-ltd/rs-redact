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
struct Login {
    user: String,
    #[redact(level = "secret")]
    password: String,
}

#[derive(Redact)]
struct Event {
    #[redact(nested)]
    logins: Vec<Login>,
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

criterion_group!(benches, consumer_api, budget_boundaries);
criterion_main!(benches);
