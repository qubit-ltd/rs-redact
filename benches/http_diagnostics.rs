// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Benchmarks adversarially long HTTP diagnostic tokens.

use std::hint::black_box;

use criterion::{
    Criterion,
    criterion_group,
    criterion_main,
};
use qubit_redact::http::HttpRedactor;

/// Measures URL suffix handling with many unmatched closing delimiters.
fn benchmark_unmatched_url_delimiters(criterion: &mut Criterion) {
    let input = format!(
        "https://alice:secret@example.test/private{}",
        ")".repeat(8_192),
    );
    let redactor = HttpRedactor::default();
    criterion.bench_function(
        "http_diagnostic/unmatched_closing_delimiters",
        |bencher| {
            bencher.iter(|| {
                black_box(redactor.redact_urls_in_text(black_box(&input)))
            });
        },
    );
}

criterion_group!(benches, benchmark_unmatched_url_delimiters);
criterion_main!(benches);
