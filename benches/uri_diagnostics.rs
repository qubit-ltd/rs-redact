// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Benchmarks bounded URI redaction across output-budget boundaries.

use std::hint::black_box;

use criterion::BenchmarkId;
use criterion::Criterion;
use criterion::Throughput;
use criterion::criterion_group;
use criterion::criterion_main;
use qubit_redact::InputOutputLimit;
use qubit_redact::RedactionPolicy;
use qubit_redact::UriRedactor;

/// Builds a URI redactor with the benchmark's fixed diagnostic budget.
fn benchmark_redactor() -> UriRedactor {
    let budget = InputOutputLimit::new(4096, 256)
        .expect("benchmark diagnostic budget is valid");
    let core = RedactionPolicy::default()
        .to_builder()
        .diagnostic_event(budget)
        .build()
        .expect("benchmark core policy is valid");
    let policy = RedactionPolicy::builder_from(&core)
        .build()
        .expect("benchmark URI policy is valid");
    UriRedactor::new(policy)
}

/// Measures URI rendering below, near, and beyond the output budget.
fn benchmark_uri_output_budgets(criterion: &mut Criterion) {
    let redactor = benchmark_redactor();
    let inputs = [("below", 2_usize), ("near", 12), ("over", 64)].map(
        |(label, count)| {
            (
                label,
                format!(
                    "https://user:secret@example.test/?{}#fragment",
                    ["password=query-secret"; 64]
                        .iter()
                        .take(count)
                        .copied()
                        .collect::<Vec<_>>()
                        .join("&"),
                ),
            )
        },
    );
    let mut group = criterion.benchmark_group("uri_diagnostic_budget");
    for (label, input) in &inputs {
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("redact", label),
            input,
            |bencher, input| {
                bencher.iter(|| {
                    let mut session = redactor.session();
                    black_box(session.uri().redact_uri_str(black_box(input)))
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, benchmark_uri_output_budgets);
criterion_main!(benches);
