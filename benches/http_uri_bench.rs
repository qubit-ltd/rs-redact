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
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;
use qubit_redact::formats::uri::UriRedactionBoundary;

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

    let metadata = [
        ("form/short", String::from("application/x-www-form-urlencoded")),
        ("form/dense-100", parameterized_form_content_type(100)),
        ("form/dense-2000", parameterized_form_content_type(2_000)),
        (
            "multipart/metadata",
            String::from("multipart/form-data; boundary=benchmark; profile=verbose"),
        ),
    ];
    let form_body: &[u8] = b"password=raw-secret&public=ok";
    let multipart_body: &[u8] =
        b"--benchmark\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nraw-secret\r\n--benchmark--\r\n";
    for (name, content_type) in &metadata {
        let body = if name.starts_with("multipart/") {
            multipart_body
        } else {
            form_body
        };
        let output = redactor.redact_http_body_with_content_type_text(BodyCapture::complete(body), Some(content_type));
        assert!(output.complete_text().is_ok(), "{name} body should complete");
        assert!(
            !output.text().as_str().contains("raw-secret"),
            "{name} should redact its secret"
        );
        if name.starts_with("form/") {
            assert!(
                output.text().as_str().contains("public=ok"),
                "{name} should preserve public data"
            );
        }
    }
    let mut group = criterion.benchmark_group("http-content-type");
    for (name, content_type) in &metadata {
        let is_multipart = name.starts_with("multipart/");
        let body = if is_multipart { multipart_body } else { form_body };
        group.throughput(Throughput::Bytes((body.len() + content_type.len()) as u64));
        group.bench_function(*name, |bencher| {
            bencher.iter(|| {
                black_box(redactor.redact_http_body_with_content_type_text(
                    BodyCapture::complete(black_box(body)),
                    Some(black_box(content_type.as_str())),
                ))
            });
        });
    }
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

    let uri = "https://example.test/?password=raw-secret";
    let standard_policy = RedactionPolicy::standard();
    let boundary = UriRedactionBoundary::new(&standard_policy);
    let redacted = boundary.redact_uri(uri);
    assert!(!redacted.text().as_str().contains("raw-secret"));
    let inspected = boundary.inspect_uri(uri).expect("benchmark URI is valid");
    assert!(inspected.contains_sensitive());

    let mut group = criterion.benchmark_group("uri-boundary");
    group.throughput(Throughput::Bytes(uri.len() as u64));
    group.bench_function("new-standard", |bencher| {
        bencher.iter(|| black_box(UriRedactionBoundary::new(black_box(&standard_policy))));
    });
    group.bench_function("new-and-redact", |bencher| {
        bencher.iter(|| black_box(UriRedactionBoundary::new(black_box(&standard_policy))).redact_uri(black_box(uri)));
    });
    group.bench_function("reuse-redact", |bencher| {
        bencher.iter(|| boundary.redact_uri(black_box(uri)));
    });
    group.bench_function("reuse-inspect", |bencher| {
        bencher.iter(|| boundary.inspect_uri(black_box(uri)));
    });
    group.finish();
}

fn parameterized_form_content_type(count: usize) -> String {
    let mut value = String::from("application/x-www-form-urlencoded");
    for index in 0..count {
        value.push_str(&format!(";p{index}=abcdefgh"));
    }
    value
}

criterion_group!(benches, benchmark_http_uri);
criterion_main!(benches);
