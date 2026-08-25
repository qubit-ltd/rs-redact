// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Representative scalar, domain, and format redaction benchmarks.

use std::hint::black_box;

use criterion::Criterion;
use criterion::criterion_group;
use criterion::criterion_main;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;

/// Benchmarks the primary one-shot redaction entry points.
fn benchmark_redaction(criterion: &mut Criterion) {
    let redactor = Redactor::standard();
    let json = r#"{"account":"account-42","token":"raw-json-secret","nested":{"password":"raw-nested-secret"}}"#;
    let json_value = serde_json::from_str(json).expect("benchmark JSON must parse");
    let truncating_policy = RedactionPolicy::builder()
        .limits(|limits| {
            let _ = limits.max_output_bytes(16);
        })
        .expect("benchmark limits must build")
        .build()
        .expect("benchmark policy must build");
    let truncating_redactor = Redactor::new(truncating_policy);
    let disabled_redactor = Redactor::new(RedactionPolicy::disabled());

    let mut group = criterion.benchmark_group("redaction");
    group.bench_function("one-shot/sensitive-field", |bencher| {
        bencher.iter(|| redactor.redact_field("password", black_box("raw-secret")));
    });
    group.bench_function("batch/single-sensitive-field", |bencher| {
        bencher.iter(|| {
            let mut batch = redactor.batch();
            let handle = batch.redact_field("password", black_box("raw-secret"));
            batch
                .finish()
                .into_resolved(handle)
                .expect("a handle created by the completed transaction must resolve")
        });
    });
    group.bench_function("composer/ordered-fields", |bencher| {
        bencher.iter(|| {
            redactor
                .text_composer()
                .literal("account=")
                .field("account", black_box("account-42"))
                .literal(" password=")
                .field("password", black_box("raw-secret"))
                .finish()
        });
    });
    group.bench_function("batch/independent-fields", |bencher| {
        bencher.iter(|| {
            let mut batch = redactor.batch();
            let _account = batch.redact_field("account", black_box("account-42"));
            let _password = batch.redact_field("password", black_box("raw-secret"));
            batch.finish()
        });
    });
    group.bench_function("json/text", |bencher| {
        bencher.iter(|| redactor.redact_json(black_box(json)));
    });
    group.bench_function("batch/single-json/text", |bencher| {
        bencher.iter(|| {
            let mut batch = redactor.batch();
            let handle = batch.redact_json(black_box(json));
            batch
                .finish()
                .into_resolved(handle)
                .expect("a handle created by the completed transaction must resolve")
        });
    });
    group.bench_function("json/borrowed-value", |bencher| {
        bencher.iter(|| redactor.redact_json_value(black_box(&json_value)));
    });
    group.bench_function("batch/single-json/borrowed-value", |bencher| {
        bencher.iter(|| {
            let mut batch = redactor.batch();
            let handle = batch.redact_json_value(black_box(&json_value));
            batch
                .finish()
                .into_resolved(handle)
                .expect("a handle created by the completed transaction must resolve")
        });
    });
    group.bench_function("unicode/scalar", |bencher| {
        bencher.iter(|| redactor.redact_field("display_name", black_box("账户🔐é")));
    });
    group.bench_function("budget/output-truncation", |bencher| {
        bencher.iter(|| truncating_redactor.redact_json(black_box(json)));
    });
    group.bench_function("policy/disabled", |bencher| {
        bencher.iter(|| disabled_redactor.redact_json(black_box(json)));
    });
    group.finish();
}

criterion_group!(benches, benchmark_redaction);
criterion_main!(benches);
