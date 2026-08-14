// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Benchmarks adversarially long HTTP diagnostic tokens.

use std::hint::black_box;

use criterion::BenchmarkId;
use criterion::Criterion;
use criterion::Throughput;
use criterion::criterion_group;
use criterion::criterion_main;
use http::HeaderMap;
use http::HeaderValue;
use qubit_redact::InputOutputLimit;
use qubit_redact::RedactionPolicy;
use qubit_redact::http::BodyBudget;
use qubit_redact::http::BodyCapture;
use qubit_redact::http::HttpRedactor;

/// Measures URL suffix handling with many unmatched closing delimiters.
fn benchmark_unmatched_url_delimiters(criterion: &mut Criterion) {
    let input = format!(
        "https://alice:secret@example.test/private{}",
        ")".repeat(8_192),
    );
    let redactor = HttpRedactor::default();
    criterion.bench_function("http_diagnostic/unmatched_closing_delimiters", |bencher| {
        bencher.iter(|| {
            let mut session = redactor.session();
            black_box(session.http().redact_urls_in_text(black_box(&input)))
        });
    });
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
    let policy = RedactionPolicy::builder()
        .body_budget(budget)
        .build()
        .expect("benchmark HTTP policy is valid");
    HttpRedactor::new(policy)
}

/// Builds an HTTP redactor using explicit diagnostic limits.
///
/// # Parameters
///
/// * `budget` - Diagnostic-input and rendered-output byte limits.
///
/// # Returns
///
/// A redactor using the validated benchmark policy.
fn redactor_with_diagnostic_budget(budget: InputOutputLimit) -> HttpRedactor {
    let policy = RedactionPolicy::builder()
        .diagnostic_event(budget)
        .build()
        .expect("benchmark HTTP policy is valid");
    HttpRedactor::new(policy)
}

/// Measures diagnostic entry points below, near, and above the input limit.
fn benchmark_diagnostic_budgets(criterion: &mut Criterion) {
    const INPUT_LIMIT: usize = 4_096;
    let redactor = redactor_with_diagnostic_budget(
        InputOutputLimit::new(INPUT_LIMIT, 512).expect("benchmark diagnostic budget is valid"),
    );
    let sizes = [
        ("below", INPUT_LIMIT / 4),
        ("near", INPUT_LIMIT - 64),
        ("over", INPUT_LIMIT * 2),
    ];
    let text_inputs =
        sizes.map(|(label, size)| (label, format!("diagnostic {}", "x".repeat(size))));
    let url_inputs = sizes.map(|(label, size)| {
        (
            label,
            format!("https://example.test/?note={}", "x".repeat(size)),
        )
    });
    let form_inputs = sizes.map(|(label, size)| (label, format!("note={}", "x".repeat(size))));
    let header_inputs = sizes.map(|(label, size)| {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-diagnostic",
            HeaderValue::from_str(&"x".repeat(size)).expect("benchmark header value is valid"),
        );
        (label, headers)
    });
    let mut group = criterion.benchmark_group("http_diagnostic_budget");

    for (label, input) in &text_inputs {
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_with_input(BenchmarkId::new("text", label), input, |bencher, input| {
            bencher.iter(|| {
                let mut session = redactor.session();
                black_box(session.http().redact_urls_in_text(black_box(input)))
            });
        });
    }
    for (label, input) in &url_inputs {
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_with_input(BenchmarkId::new("url", label), input, |bencher, input| {
            bencher.iter(|| {
                let mut session = redactor.session();
                black_box(session.http().redact_url_str(black_box(input)))
            });
        });
    }
    for (label, input) in &form_inputs {
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_with_input(BenchmarkId::new("form", label), input, |bencher, input| {
            bencher.iter(|| {
                let mut session = redactor.session();
                black_box(session.http().redact_form(black_box(input)))
            });
        });
    }
    for (label, headers) in &header_inputs {
        group.bench_with_input(
            BenchmarkId::new("headers", label),
            headers,
            |bencher, headers| {
                bencher.iter(|| {
                    let mut session = redactor.session();
                    black_box(session.http().redact_headers(black_box(headers)))
                });
            },
        );
    }
    group.finish();
}

/// Measures structured bodies, source truncation, and a tight output budget.
fn benchmark_body_redaction(criterion: &mut Criterion) {
    let json = br#"{"password":"raw-password","profile":{"api_key":"raw-api-key","label":"visible"},"items":[{"token":"raw-token","count":1},{"name":"visible"}]}"#;
    let form = b"password=raw-password&api_key=raw-api-key&label=visible&note=representative+text";
    let multipart = b"--bench\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nraw-password\r\n--bench\r\nContent-Disposition: form-data; name=\"profile\"\r\nContent-Type: application/json\r\n\r\n{\"api_key\":\"raw-api-key\",\"label\":\"visible\"}\r\n--bench--\r\n";
    let json_type = HeaderValue::from_static("application/json");
    let form_type = HeaderValue::from_static("application/x-www-form-urlencoded");
    let multipart_type = HeaderValue::from_static("multipart/form-data; boundary=bench");
    let default_redactor = HttpRedactor::default();
    let tight_redactor =
        redactor_with_budget(BodyBudget::new(4_096, 64).expect("tight benchmark budget is valid"));
    let truncated = BodyCapture::truncated(&json[..json.len() / 2], json.len())
        .expect("benchmark capture truthfully reports omitted bytes");
    let mut group = criterion.benchmark_group("http_body_redaction");

    group.throughput(Throughput::Bytes(json.len() as u64));
    group.bench_function("json", |bencher| {
        bencher.iter(|| {
            let mut session = default_redactor.session();
            black_box(session.http().redact_body(
                black_box(BodyCapture::complete(json)),
                Some(black_box(&json_type)),
            ))
        });
    });

    group.throughput(Throughput::Bytes(form.len() as u64));
    group.bench_function("form", |bencher| {
        bencher.iter(|| {
            let mut session = default_redactor.session();
            black_box(session.http().redact_body(
                black_box(BodyCapture::complete(form)),
                Some(black_box(&form_type)),
            ))
        });
    });

    group.throughput(Throughput::Bytes(multipart.len() as u64));
    group.bench_function("multipart", |bencher| {
        bencher.iter(|| {
            let mut session = default_redactor.session();
            black_box(session.http().redact_body(
                black_box(BodyCapture::complete(multipart)),
                Some(black_box(&multipart_type)),
            ))
        });
    });

    group.throughput(Throughput::Bytes(truncated.captured_len() as u64));
    group.bench_function("source_truncated_json", |bencher| {
        bencher.iter(|| {
            let mut session = default_redactor.session();
            black_box(
                session
                    .http()
                    .redact_body(black_box(truncated), Some(black_box(&json_type))),
            )
        });
    });

    group.throughput(Throughput::Bytes(json.len() as u64));
    group.bench_function("tight_output_budget", |bencher| {
        bencher.iter(|| {
            let mut session = tight_redactor.session();
            black_box(session.http().redact_body(
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
    benchmark_diagnostic_budgets,
    benchmark_body_redaction,
);
criterion_main!(benches);
