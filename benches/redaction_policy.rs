// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Benchmarks policy snapshot creation and field classification.

use std::{collections::BTreeMap, hint::black_box};

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use qubit_redact::{
    FieldNameMatching, LogOutputLimit, RedactedMap, RedactionPolicy, Redactor, Sensitivity,
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
        bencher.iter(|| black_box(exact.sensitivity_for(black_box("access_token"))));
    });
    group.bench_function("exact_miss", |bencher| {
        bencher.iter(|| black_box(exact.sensitivity_for(black_box("public_identifier"))));
    });
    group.bench_function("suffix_hit", |bencher| {
        bencher.iter(|| black_box(suffix.sensitivity_for(black_box("serviceAccessToken"))));
    });
    group.bench_function("suffix_miss", |bencher| {
        bencher.iter(|| black_box(suffix.sensitivity_for(black_box("servicePublicIdentifier"))));
    });
    group.finish();
}

/// Builds deterministic text entries for Map benchmarks.
///
/// # Parameters
///
/// * `size` - Number of entries to create.
///
/// # Returns
///
/// A key-ordered map with distinct values.
fn benchmark_map(size: usize) -> BTreeMap<String, String> {
    (0..size)
        .map(|index| {
            (
                format!("field_{index:04}"),
                format!("value_{index:04}_with_representative_text"),
            )
        })
        .collect()
}

/// Builds a policy classifying every fourth benchmark entry.
///
/// # Parameters
///
/// * `size` - Number of entries in the matching fixture.
/// * `mixed_hits` - Whether to add sensitive field rules.
///
/// # Returns
///
/// A validated benchmark policy.
fn benchmark_map_policy(size: usize, mixed_hits: bool) -> RedactionPolicy {
    let mut builder = RedactionPolicy::empty_builder();
    if mixed_hits {
        for index in (0..size).step_by(4) {
            let field = format!("field_{index:04}");
            builder = builder.raise(&field, Sensitivity::Secret);
        }
    }
    builder.build().expect("benchmark field rules are valid")
}

/// Measures Map view formatting, copy, and in-place paths across sizes and
/// classification hit rates.
fn benchmark_map_redaction(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("map_redaction");
    let output_limit =
        LogOutputLimit::new(256).expect("benchmark output limit should contain the marker");
    for (size_name, size) in [("small", 8usize), ("large", 256usize)] {
        let map = benchmark_map(size);
        for (scenario, mixed_hits) in [("miss", false), ("mixed", true)] {
            let policy = benchmark_map_policy(size, mixed_hits);
            let redactor = Redactor::new(policy.clone());
            let parameter = format!("{size_name}_{size}/{scenario}");
            group.throughput(Throughput::Elements(size as u64));

            group.bench_with_input(
                BenchmarkId::new("view_format", &parameter),
                &map,
                |bencher, input| {
                    bencher.iter(|| {
                        let view = RedactedMap::new(black_box(input), policy.clone());
                        black_box(format!("{view:?}"))
                    });
                },
            );
            group.bench_with_input(
                BenchmarkId::new("display_streaming", &parameter),
                &map,
                |bencher, input| {
                    bencher.iter(|| {
                        let view = RedactedMap::new(black_box(input), policy.clone());
                        black_box(view.to_string())
                    });
                },
            );
            group.bench_with_input(
                BenchmarkId::new("display_bounded", &parameter),
                &map,
                |bencher, input| {
                    bencher.iter(|| {
                        let view = RedactedMap::new(black_box(input), policy.clone());
                        black_box(view.with_output_limit(output_limit).to_string())
                    });
                },
            );
            group.bench_with_input(
                BenchmarkId::new("copy", &parameter),
                &map,
                |bencher, input| {
                    bencher.iter(|| black_box(redactor.redact_map(black_box(input))));
                },
            );
            group.bench_with_input(
                BenchmarkId::new("in_place", &parameter),
                &map,
                |bencher, input| {
                    bencher.iter_batched(
                        || input.clone(),
                        |mut candidate| {
                            redactor.redact_map_in_place(black_box(&mut candidate));
                            black_box(candidate)
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
    group.finish();
}

criterion_group!(
    benches,
    benchmark_policy_snapshot,
    benchmark_field_classification,
    benchmark_map_redaction,
);
criterion_main!(benches);
