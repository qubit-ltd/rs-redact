// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Representative HTTP and URI format benchmarks.

use std::hint::black_box;

use criterion::Criterion;
use criterion::Throughput;
use criterion::criterion_group;
use criterion::criterion_main;
use http::HeaderMap;
use http::HeaderValue;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

/// Benchmarks URL, URI, header, and structured HTTP body redaction.
fn benchmark_http_uri(criterion: &mut Criterion) {
    let redactor = Redactor::standard();
    let url = "https://user:password@example.test/api/items?account=42&token=raw-secret#fragment";
    let mut headers = HeaderMap::new();
    headers.insert("authorization", HeaderValue::from_static("Bearer raw-secret"));
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    let content_type = HeaderValue::from_static("application/json");
    let body = br#"{"account":"42","token":"raw-secret","items":[1,2,3,4]}"#;

    let mut group = criterion.benchmark_group("http-uri-formats");
    group.throughput(Throughput::Bytes(url.len() as u64));
    group.bench_function("http/url", |bencher| {
        bencher.iter(|| redactor.redact_http_url(black_box(url)));
    });
    group.bench_function("uri/value", |bencher| {
        bencher.iter(|| redactor.redact_uri(black_box(url)));
    });
    group.throughput(Throughput::Elements(headers.len() as u64));
    group.bench_function("http/headers", |bencher| {
        bencher.iter(|| redactor.redact_http_headers(black_box(&headers)));
    });
    group.throughput(Throughput::Bytes(body.len() as u64));
    group.bench_function("http/json-body", |bencher| {
        bencher.iter(|| redactor.redact_http_body(BodyCapture::complete(black_box(body)), Some(&content_type)));
    });
    group.finish();

    let long_query = (0..128)
        .map(|index| format!("field{index}=value{index}"))
        .collect::<Vec<_>>()
        .join("&");
    let long_url = format!("https://example.test/path?{long_query}");
    let mut nested_url = String::from("https://inner.test/path?password=raw-secret");
    for _ in 0..3 {
        nested_url = url::Url::parse_with_params("https://outer.test/", &[("next", nested_url.as_str())])
            .expect("nested benchmark URL is valid")
            .to_string();
    }
    let url_cases = [
        ("short", url),
        ("long-query", long_url.as_str()),
        ("nested", nested_url.as_str()),
    ];
    for (name, input) in url_cases {
        let output = redactor.redact_http_url(input);
        assert!(output.complete_text().is_ok(), "{name} URL should be complete");
        assert!(
            !output.text().as_str().contains("raw-secret"),
            "{name} URL should be redacted"
        );
        let mut batch = redactor.diagnostic_batch();
        let handle = batch.redact_http_url(input);
        let output = batch.finish();
        assert!(
            !output.text(handle).as_str().contains("raw-secret"),
            "{name} batch URL should be redacted"
        );

        let mut group = criterion.benchmark_group(format!("http-url-{name}"));
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_function("one-shot", |bencher| {
            bencher.iter(|| redactor.redact_http_url(black_box(input)));
        });
        group.bench_function("single-item-batch", |bencher| {
            bencher.iter(|| {
                let mut batch = redactor.diagnostic_batch();
                let handle = batch.redact_http_url(black_box(input));
                black_box(batch.finish().text(handle));
            });
        });
        group.finish();
    }
}

criterion_group!(benches, benchmark_http_uri);
criterion_main!(benches);
