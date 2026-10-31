// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Representative scalar, domain, and format redaction benchmarks.

use std::ffi::OsStr;
use std::hint::black_box;

use criterion::Criterion;
use criterion::Throughput;
use criterion::criterion_group;
use criterion::criterion_main;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::formats::argv::ArgvItem;

/// Benchmarks the primary one-shot redaction entry points.
fn benchmark_redaction(criterion: &mut Criterion) {
    let redactor = Redactor::standard();
    let json = r#"{"account":"account-42","token":"raw-json-secret","nested":{"password":"raw-nested-secret"}}"#;
    let json_value = serde_json::from_str(json).expect("benchmark JSON must parse");
    let mut object_128 = (0..126)
        .map(|index| {
            let key = if index % 2 == 0 {
                format!("field-{index}")
            } else {
                format!("customer-password-{index}")
            };
            (key, serde_json::Value::String(format!("value-{index}")))
        })
        .collect::<serde_json::Map<_, _>>();
    object_128.insert(
        "password".to_owned(),
        serde_json::Value::String("value-secret".to_owned()),
    );
    object_128.insert(
        "PASSWORD".to_owned(),
        serde_json::Value::String("value-normalized-secret".to_owned()),
    );
    let object_128 = serde_json::Value::Object(object_128);
    let object_128_text = serde_json::to_string(&object_128).expect("benchmark object must serialize");
    let fixture_output = redactor.redact_json_value(&object_128);
    let fixture_json: serde_json::Value =
        serde_json::from_str(fixture_output.text().as_ref()).expect("benchmark fixture output should be JSON");
    let expected_mask = redactor.policy().masking().mask_opaque(Sensitivity::Secret);
    assert_eq!(
        fixture_json["password"], expected_mask,
        "fixture should include a classified key",
    );
    assert_eq!(
        fixture_json["PASSWORD"], expected_mask,
        "fixture should include a normalized key",
    );
    assert_eq!(fixture_json.as_object().map(serde_json::Map::len), Some(128));
    let fixture_text_output = redactor.redact_json(&object_128_text);
    let fixture_text_json: serde_json::Value = serde_json::from_str(fixture_text_output.text().as_ref())
        .expect("text benchmark fixture output should be JSON");
    assert_eq!(
        fixture_text_json, fixture_json,
        "text and Value fixtures should redact equally",
    );
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
            let mut batch = redactor.diagnostic_batch();
            let handle = batch.redact_field("password", black_box("raw-secret"));
            let output = batch.finish_with_marker("<redaction incomplete>");
            black_box(output.text(handle));
            output
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
            let mut batch = redactor.diagnostic_batch();
            let _account = batch.redact_field("account", black_box("account-42"));
            let _password = batch.redact_field("password", black_box("raw-secret"));
            batch.finish_with_marker("<redaction incomplete>")
        });
    });
    group.bench_function("json/text", |bencher| {
        bencher.iter(|| redactor.redact_json(black_box(json)));
    });
    group.bench_function("batch/single-json/text", |bencher| {
        bencher.iter(|| {
            let mut batch = redactor.diagnostic_batch();
            let handle = batch.redact_json(black_box(json));
            let output = batch.finish_with_marker("<redaction incomplete>");
            black_box(output.text(handle));
            output
        });
    });
    group.bench_function("json/borrowed-value", |bencher| {
        bencher.iter(|| redactor.redact_json_value(black_box(&json_value)));
    });
    group.bench_function("json/object-128/text", |bencher| {
        bencher.iter(|| redactor.redact_json(black_box(&object_128_text)));
    });
    group.bench_function("json/object-128/borrowed-value", |bencher| {
        bencher.iter(|| redactor.redact_json_value(black_box(&object_128)));
    });
    group.bench_function("batch/single-json/borrowed-value", |bencher| {
        bencher.iter(|| {
            let mut batch = redactor.diagnostic_batch();
            let handle = batch.redact_json_value(black_box(&json_value));
            let output = batch.finish_with_marker("<redaction incomplete>");
            black_box(output.text(handle));
            output
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

    let overlapping_policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .disable_floor()
                .matching(qubit_redact::FieldNameMatching::ExactOrTokenSuffix)
                .high_sensitive("access_token")
                .secret_sensitive("openai_access_token")
                .medium_sensitive("password")
                .low_sensitive("content_type");
        })
        .expect("overlapping benchmark rules should be valid")
        .build()
        .expect("benchmark policy should build");
    let field_names = [
        "password",
        "PASSWORD",
        "access_token",
        "Content-Type",
        "OPENAI_ACCESS_TOKEN",
    ];
    let rules = RedactionPolicy::standard().rules().clone();
    let overlapping_rules = overlapping_policy.rules().clone();
    let mut group = criterion.benchmark_group("field-classification");
    group.bench_function("standard-floor/workload", |bencher| {
        bencher.iter(|| {
            for field in field_names {
                black_box(rules.sensitivity_for(black_box(field)));
            }
        });
    });
    group.bench_function("explicit-overlap/workload", |bencher| {
        bencher.iter(|| {
            for field in field_names {
                black_box(overlapping_rules.sensitivity_for(black_box(field)));
            }
        });
    });
    group.finish();

    let arguments = (0..64).map(|index| format!("argument-{index}")).collect::<Vec<_>>();
    let variables = (0..64)
        .map(|index| (format!("PUBLIC_{index}"), format!("value-{index}")))
        .collect::<Vec<_>>();
    let mut formats = criterion.benchmark_group("process-formats");
    formats.throughput(Throughput::Elements(64));
    formats.bench_function("argv/64-items", |bencher| {
        bencher.iter(|| {
            let items = arguments.iter().enumerate().map(|(index, value)| {
                if index == 63 {
                    ArgvItem::sensitive(OsStr::new(value), Sensitivity::Secret)
                } else {
                    ArgvItem::plain(OsStr::new(value))
                }
            });
            redactor.redact_argv(black_box(items))
        });
    });
    formats.bench_function("environment/64-pairs", |bencher| {
        bencher.iter(|| {
            let pairs = variables
                .iter()
                .map(|(name, value)| (OsStr::new(name), OsStr::new(value)));
            redactor.redact_env_pairs(black_box(pairs))
        });
    });
    // Each element is one argument or environment pair; the fixed program is
    // excluded.
    formats.throughput(Throughput::Elements((arguments.len() + variables.len()) as u64));
    formats.bench_function("process/64-arguments-and-variables", |bencher| {
        bencher.iter(|| {
            let items = arguments.iter().map(|value| ArgvItem::plain(OsStr::new(value)));
            let pairs = variables
                .iter()
                .map(|(name, value)| (OsStr::new(name), OsStr::new(value)));
            redactor.redact_process(OsStr::new("client"), black_box(items), black_box(pairs))
        });
    });
    formats.finish();
}

criterion_group!(benches, benchmark_redaction);
criterion_main!(benches);
