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
}

criterion_group!(benches, benchmark_http_uri);
criterion_main!(benches);
