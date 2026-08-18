// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::RedactionReasons;
use qubit_redact::RedactionSummary;
use qubit_redact::RedactionUsage;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::config::RedactionConfig;
use qubit_redact::config::RedactionConfigBuilder;
use qubit_redact::domain::Redact;
use qubit_redact::domain::RedactionWriter;

struct Account {
    name: String,
    _password: String,
}

impl Redact for Account {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_, '_>) {
        writer.record("Account", |fields| {
            let _ = fields
                .field("name", || self.name.clone())
                .sensitive(Sensitivity::Secret, "password", || {
                    panic!("secret accessor must not run")
                });
        });
    }
}

#[test]
fn test_transactional_field_builder_and_structured_writer() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            let _ = fields
                .secret_sensitive("password")
                .high_sensitive("access_token")
                .sensitive(Sensitivity::Medium, "birthday");
        })
        .expect("field configuration should be valid")
        .build()
        .expect("policy should build");

    let output = Redactor::new(policy).redact(&Account {
        name: "ada".to_owned(),
        _password: "raw-password".to_owned(),
    });
    assert!(output.text().as_str().contains("ada"));
    assert!(!output.text().as_str().contains("raw-password"));
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    assert!(output.summary().usage().emitted_output_bytes() > 0);
    assert!(output.summary().usage().visited_nodes() > 0);
}

#[test]
fn test_set_default_replaces_only_future_snapshots() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            let _ = fields.secret_sensitive("password");
        })
        .expect("field configuration should be valid")
        .build()
        .expect("policy should build");
    let replacement = Redactor::new(policy);
    let old = Redactor::set_default(replacement.clone());
    let current = Redactor::current_default();
    assert_eq!(current.policy().sensitivity_for("password"), Some(Sensitivity::Secret));
    let restored = Redactor::set_default(old.clone());
    assert_eq!(restored.policy(), replacement.policy());
}

#[test]
fn test_chain_session_returns_final_displayable_text() {
    let output = Redactor::standard()
        .session()
        .text("request failed: ")
        .field("request_id", "abc")
        .value(
            "metadata",
            &Account {
                name: "ada".to_owned(),
                _password: "raw-password".to_owned(),
            },
        )
        .finish();
    assert!(output.text().to_string().contains("request failed"));
    assert!(!output.text().as_str().contains("raw-password"));
}

#[test]
fn test_output_and_summary_accessors_preserve_machine_readable_state() {
    let usage = RedactionUsage::default();
    assert_eq!(usage.inspected_input_bytes(), 0);
    assert_eq!(usage.emitted_output_bytes(), 0);
    assert_eq!(usage.visited_nodes(), 0);
    assert_eq!(usage.visited_collection_items(), 0);
    assert_eq!(usage.maximum_depth(), 0);

    let reasons = RedactionReasons::empty()
        .with(RedactionReason::OutputLimitReached)
        .with(RedactionReason::DepthLimitReached);
    assert!(reasons.contains(RedactionReason::OutputLimitReached));
    assert!(reasons.contains(RedactionReason::DepthLimitReached));

    let truncated = RedactionSummary::truncated(RedactionReason::InputLimitReached);
    assert_eq!(truncated.completion(), RedactionCompletion::Truncated);
    assert!(truncated.reasons().contains(RedactionReason::InputLimitReached));
    assert_eq!(truncated.usage(), usage);
    assert_eq!(
        RedactionSummary::exhausted().completion(),
        RedactionCompletion::Exhausted
    );

    let output = Redactor::standard().redact(&Account {
        name: "ada".to_owned(),
        _password: "secret".to_owned(),
    });
    let (text, summary) = output.into_parts();
    assert!(!text.into_string().contains("secret"));
    assert_eq!(summary.completion(), RedactionCompletion::Complete);

    let output = Redactor::standard().redact(&Account {
        name: "ada".to_owned(),
        _password: "secret".to_owned(),
    });
    assert!(!output.into_text().as_str().contains("secret"));
}

#[test]
fn test_configuration_builder_produces_standard_snapshot() {
    let config = RedactionConfigBuilder::standard()
        .build()
        .expect("standard configuration should build");
    assert_eq!(config, RedactionConfig::standard());
    let default_config = RedactionConfigBuilder::default()
        .build()
        .expect("default configuration should build");
    assert_eq!(default_config, config);
}

#[cfg(all(feature = "http", feature = "json", feature = "uri"))]
#[test]
fn test_chain_adapter_namespaces_accept_closures() {
    let redactor = Redactor::standard();
    let session = redactor
        .session()
        .argv_with(|_| {})
        .env_with(|_| {})
        .http_with(|_| {})
        .json_with(|_| {})
        .uri_with(|_| {});
    let _ = session.finish();

    let mut session = redactor.session();
    let _: () = session.argv_with_mut(|_| {});
    let _: () = session.env_with_mut(|_| {});
    let _: () = session.http_with_mut(|_| {});
    let _: () = session.json_with_mut(|_| {});
    let _: () = session.uri_with_mut(|_| {});
}
