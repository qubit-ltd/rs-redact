// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Benchmarks policy snapshot creation and field classification.

use std::hint::black_box;

use criterion::{
    Criterion,
    criterion_group,
    criterion_main,
};
use qubit_redact::{
    FieldNameMatching,
    RedactionPolicy,
    Sensitivity,
};

/// Compares the global-default snapshot path with a direct standard clone.
fn benchmark_policy_snapshot(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("policy_snapshot");
    group.bench_function("default", |bencher| {
        bencher.iter(|| black_box(RedactionPolicy::default()));
    });
    group.bench_function("standard", |bencher| {
        bencher.iter(|| black_box(RedactionPolicy::standard()));
    });
    group.finish();
}

/// Measures isolated exact and semantic-suffix classification paths.
fn benchmark_field_classification(criterion: &mut Criterion) {
    let exact = RedactionPolicy::empty_builder()
        .matching(FieldNameMatching::Exact)
        .raise("access_token", Sensitivity::Secret)
        .build()
        .expect("exact benchmark policy should be valid");
    let suffix = RedactionPolicy::empty_builder()
        .matching(FieldNameMatching::ExactOrTokenSuffix)
        .raise("access_token", Sensitivity::Secret)
        .build()
        .expect("suffix benchmark policy should be valid");
    let mut group = criterion.benchmark_group("field_classification");

    group.bench_function("exact_hit", |bencher| {
        bencher.iter(|| {
            black_box(exact.sensitivity_for(black_box("access_token")))
        });
    });
    group.bench_function("exact_miss", |bencher| {
        bencher.iter(|| {
            black_box(exact.sensitivity_for(black_box("public_identifier")))
        });
    });
    group.bench_function("suffix_hit", |bencher| {
        bencher.iter(|| {
            black_box(suffix.sensitivity_for(black_box("serviceAccessToken")))
        });
    });
    group.bench_function("suffix_miss", |bencher| {
        bencher.iter(|| {
            black_box(
                suffix.sensitivity_for(black_box("servicePublicIdentifier")),
            )
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    benchmark_policy_snapshot,
    benchmark_field_classification,
);
criterion_main!(benches);
