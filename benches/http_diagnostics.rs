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
    Throughput,
    criterion_group,
    criterion_main,
};
use http::HeaderValue;
use qubit_redact::http::{
    BodyBudget,
    BodyCapture,
    HttpRedactionPolicy,
    HttpRedactor,
};

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

/// Builds an HTTP redactor using explicit body limits.
///
/// # Parameters
///
/// * `budget` - Parser-input and rendered-output byte limits.
///
/// # Returns
///
/// A redactor using the validated benchmark policy.
fn redactor_with_budget(budget: BodyBudget) -> HttpRedactor {
    let policy = HttpRedactionPolicy::builder()
        .body_budget(budget)
        .build()
        .expect("benchmark HTTP policy is valid");
    HttpRedactor::new(policy)
}

/// Measures structured bodies, source truncation, and a tight output budget.
fn benchmark_body_redaction(criterion: &mut Criterion) {
    let json = br#"{"password":"raw-password","profile":{"api_key":"raw-api-key","label":"visible"},"items":[{"token":"raw-token","count":1},{"name":"visible"}]}"#;
    let form = b"password=raw-password&api_key=raw-api-key&label=visible&note=representative+text";
    let multipart = b"--bench\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nraw-password\r\n--bench\r\nContent-Disposition: form-data; name=\"profile\"\r\nContent-Type: application/json\r\n\r\n{\"api_key\":\"raw-api-key\",\"label\":\"visible\"}\r\n--bench--\r\n";
    let json_type = HeaderValue::from_static("application/json");
    let form_type =
        HeaderValue::from_static("application/x-www-form-urlencoded");
    let multipart_type =
        HeaderValue::from_static("multipart/form-data; boundary=bench");
    let default_redactor = HttpRedactor::default();
    let tight_redactor = redactor_with_budget(
        BodyBudget::new(4_096, 64).expect("tight benchmark budget is valid"),
    );
    let truncated =
        BodyCapture::truncated(&json[..json.len() / 2], Some(json.len()))
            .expect("benchmark capture truthfully reports omitted bytes");
    let mut group = criterion.benchmark_group("http_body_redaction");

    group.throughput(Throughput::Bytes(json.len() as u64));
    group.bench_function("json", |bencher| {
        bencher.iter(|| {
            black_box(default_redactor.redact_body(
                black_box(BodyCapture::complete(json)),
                Some(black_box(&json_type)),
            ))
        });
    });

    group.throughput(Throughput::Bytes(form.len() as u64));
    group.bench_function("form", |bencher| {
        bencher.iter(|| {
            black_box(default_redactor.redact_body(
                black_box(BodyCapture::complete(form)),
                Some(black_box(&form_type)),
            ))
        });
    });

    group.throughput(Throughput::Bytes(multipart.len() as u64));
    group.bench_function("multipart", |bencher| {
        bencher.iter(|| {
            black_box(default_redactor.redact_body(
                black_box(BodyCapture::complete(multipart)),
                Some(black_box(&multipart_type)),
            ))
        });
    });

    group.throughput(Throughput::Bytes(truncated.captured_len() as u64));
    group.bench_function("source_truncated_json", |bencher| {
        bencher.iter(|| {
            black_box(
                default_redactor.redact_body(
                    black_box(truncated),
                    Some(black_box(&json_type)),
                ),
            )
        });
    });

    group.throughput(Throughput::Bytes(json.len() as u64));
    group.bench_function("tight_output_budget", |bencher| {
        bencher.iter(|| {
            black_box(tight_redactor.redact_body(
                black_box(BodyCapture::complete(json)),
                Some(black_box(&json_type)),
            ))
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    benchmark_unmatched_url_delimiters,
    benchmark_body_redaction,
);
criterion_main!(benches);
