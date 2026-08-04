// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![no_main]

use fluent_uri::Uri;
use libfuzzer_sys::fuzz_target;
use qubit_redact::{
    InputOutputLimit,
    MaskPolicy,
    RedactionPolicy,
    Sensitivity,
    UriComponent,
    UriFragmentPolicy,
    UriPathPolicy,
    RedactionPolicy,
    UriRedactionReason,
    UriRedactionStatus,
    UriRedactor,
};

const INPUT_LIMIT: usize = 4096;
const OUTPUT_LIMIT: usize = 128;
const FUZZ_SECRET: &str = "qubit-uri-fuzz-secret-4a1b";

/// Checks the structural invariants promised by URI redaction results.
fn assert_uri_result_invariants(result: &qubit_redact::UriRedaction) {
    let components = [
        UriComponent::Username,
        UriComponent::Password,
        UriComponent::Query,
        UriComponent::Path,
        UriComponent::Fragment,
    ];
    let sensitive_components = components
        .into_iter()
        .filter(|component| result.has_sensitive_component(*component))
        .collect::<Vec<_>>();
    let sensitive_reasons = result
        .reasons()
        .iter()
        .filter_map(|reason| match reason {
            UriRedactionReason::SensitiveComponent(component) => {
                Some(*component)
            }
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(
        sensitive_components.len(),
        sensitive_reasons.len(),
        "every sensitive component has exactly one matching reason",
    );
    for component in sensitive_components {
        assert!(
            sensitive_reasons.contains(&component),
            "missing reason for {component:?}",
        );
    }
    match result.status() {
        UriRedactionStatus::PassedThrough => {
            assert!(sensitive_reasons.is_empty());
        }
        UriRedactionStatus::Redacted => {
            assert!(!sensitive_reasons.is_empty());
        }
        UriRedactionStatus::Invalid => {
            assert!(sensitive_reasons.is_empty());
            assert!(!result.has_sensitive_components());
        }
        _ => {}
    }

    let output = result.log_safe_text().as_str();
    for (index, byte) in output.bytes().enumerate() {
        if byte == b'%' {
            let suffix = output.as_bytes().get(index + 1..index + 3);
            assert!(
                suffix.is_some_and(|bytes| bytes.len() == 2
                    && bytes[0].is_ascii_hexdigit()
                    && bytes[1].is_ascii_hexdigit()),
                "output contains an incomplete percent escape: {output:?}",
            );
        }
    }

    if result.status() != UriRedactionStatus::Invalid && !result.is_truncated()
    {
        assert!(
            Uri::<&str>::parse(output).is_ok(),
            "non-invalid, non-truncated output is not parseable: {output:?}",
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let bounded = &data[..data.len().min(INPUT_LIMIT)];
    let arbitrary = String::from_utf8_lossy(bounded);
    let default_redactor = UriRedactor::default();
    let first = default_redactor.redact_uri_str(&arbitrary);
    let second = default_redactor.redact_uri_str(&arbitrary);
    assert_eq!(first, second);
    assert_uri_result_invariants(&first);
    assert!(
        first.log_safe_text().as_ref().len()
            <= default_redactor
                .policy()
                .limits().diagnostic_event()
                .max_output_bytes()
    );

    let budget = InputOutputLimit::new(INPUT_LIMIT, OUTPUT_LIMIT)
        .expect("the URI fuzz budget is valid");
    let core = RedactionPolicy::default()
        .to_builder()
        .diagnostic_event(budget)
        .build()
        .expect("the core fuzz policy is valid");
    let policy = RedactionPolicy::builder_from(&core)
        .path_policy(UriPathPolicy::Redact)
        .fragment_policy(UriFragmentPolicy::Redact)
        .build()
        .expect("the URI fuzz policy is valid");
    let redactor = UriRedactor::new(policy);
    let noise = bounded
        .iter()
        .take(32)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let uri = format!(
        "https://user:{FUZZ_SECRET}@example.test/path/{FUZZ_SECRET}?password={FUZZ_SECRET}&noise={noise}#{FUZZ_SECRET}"
    );
    let result = redactor.redact_uri_str(&uri);
    assert_eq!(result, redactor.redact_uri_str(&uri));
    assert_uri_result_invariants(&result);
    assert!(result.log_safe_text().as_ref().len() <= OUTPUT_LIMIT);
    assert!(!result.log_safe_text().as_ref().contains(FUZZ_SECRET));

    let custom_core = RedactionPolicy::default()
        .to_builder()
        .diagnostic_event(
            InputOutputLimit::new(INPUT_LIMIT, INPUT_LIMIT)
                .expect("the custom URI fuzz budget is valid"),
        )
        .mask(Sensitivity::Secret, MaskPolicy::fixed("密\n/?#%"))
        .expect("the custom secret mask is valid")
        .mask(Sensitivity::High, MaskPolicy::fixed("密\n/?#%"))
        .expect("the custom high mask is valid")
        .build()
        .expect("the custom URI fuzz policy is valid");
    let custom_policy = RedactionPolicy::builder_from(&custom_core)
        .path_policy(UriPathPolicy::Redact)
        .fragment_policy(UriFragmentPolicy::Redact)
        .build()
        .expect("the custom URI policy is valid");
    let custom_result = UriRedactor::new(custom_policy)
        .redact_uri_str("https://example.test/path?password=secret#fragment");
    assert_uri_result_invariants(&custom_result);
    assert_eq!(custom_result.status(), UriRedactionStatus::Redacted);
    assert!(!custom_result.is_truncated());
    assert!(!custom_result.log_safe_text().as_ref().contains("secret"));
});
