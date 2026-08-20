// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public transaction-session contract tests.

use std::cell::Cell;
use std::ffi::OsStr;
use std::fmt;
use std::panic::AssertUnwindSafe;
use std::rc::Rc;

use qubit_redact::MaskPolicy;
use qubit_redact::Redact;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionHandleError;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::formats::argv::ArgvItem;
#[cfg(feature = "http")]
use qubit_redact::formats::http::BodyCapture;

/// A domain value whose user-supplied redaction code panics deliberately.
struct PanicValue;

impl Redact for PanicValue {
    fn write_redacted(&self, _writer: &mut RedactionWriter<'_>) {
        panic!("test panic");
    }
}

/// A panic that occurs after a writer has already appended transaction-owned
/// output. This distinguishes rollback from merely avoiding an initial write.
struct PartiallyWrittenPanicValue;

impl Redact for PartiallyWrittenPanicValue {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.literal("must-not-publish");
        panic!("test partial-write panic");
    }
}

/// A simple hand-written domain value for exercising the convenience facade.
struct SafeValue;

impl Redact for SafeValue {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.literal("value");
    }
}

/// A hand-written value with one explicitly unredacted field and one field
/// whose fixed sensitivity must prevent source access.
struct WriterContractValue;

impl Redact for WriterContractValue {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("WriterContractValue", |fields| {
            fields.unredacted("id", || 7_u8);
            fields.sensitive(Sensitivity::Secret, "token", || panic!("secret accessor must not run"));
        });
    }
}

/// A domain value that verifies `sensitive` merges its explicit minimum with
/// the runtime field policy before deciding whether source access is safe.
struct RuntimeSensitiveWriterContractValue;

impl Redact for RuntimeSensitiveWriterContractValue {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("RuntimeSensitiveWriterContractValue", |fields| {
            fields.sensitive(Sensitivity::Low, "runtime_secret", || {
                panic!("a policy-raised secret accessor must not run")
            });
            fields.sensitive(Sensitivity::High, "explicit_high", || {
                panic!("an explicit high accessor must not run")
            });
        });
    }
}

/// A writer value large enough to exercise its shared output admission.
struct WriterLargeValue;

impl Redact for WriterLargeValue {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Large", |fields| {
            fields.unredacted("payload", || "a value that exceeds the transaction output budget");
        });
    }
}

/// Exercises a non-secret field's bounded `Debug` capture and masking path.
struct WriterLowSensitivityValue {
    accessed: Rc<Cell<bool>>,
}

impl Redact for WriterLowSensitivityValue {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Low", |fields| {
            fields.sensitive(Sensitivity::Low, "note", || {
                self.accessed.set(true);
                "visible note"
            });
        });
    }
}

/// A `Debug` implementation that exposes whether formatting continued beyond
/// the first chunk after the writer's output budget had already closed.
struct DebugStopsAtBudget {
    visited_after_first_chunk: Rc<Cell<bool>>,
}

impl fmt::Debug for DebugStopsAtBudget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("first-chunk-that-overflows-the-budget")?;
        self.visited_after_first_chunk.set(true);
        formatter.write_str("second-chunk")
    }
}

/// A domain value whose first unredacted field must close the writer before
/// the `Debug` implementation can produce its second chunk or any later field
/// accessor can run.
struct WriterBudgetStopValue {
    debug_value: DebugStopsAtBudget,
    later_accessor_called: Rc<Cell<bool>>,
}

/// A leaf used to exercise all public structured-writer shapes through one
/// completed transaction.
struct WriterShapeLeaf;

impl Redact for WriterShapeLeaf {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.unit("Leaf");
    }
}

/// A hand-written domain value that uses nested-list and nested-value
/// operations through its parent transaction.
struct WriterShapesValue;

impl Redact for WriterShapesValue {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Shapes", |fields| {
            fields
                .list(|items| {
                    items.nested_item(&WriterShapeLeaf).nested_item(&WriterShapeLeaf);
                })
                .nested("leaf", &WriterShapeLeaf);
        });
    }
}

/// A tuple-shaped value exercises the writer's tuple delimiter path.
struct WriterTupleValue;

impl Redact for WriterTupleValue {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.tuple("Pair", |fields| {
            fields.nested_item(&WriterShapeLeaf).nested_item(&WriterShapeLeaf);
        });
    }
}

impl Redact for WriterBudgetStopValue {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Budget", |fields| {
            fields.unredacted("payload", || &self.debug_value);
            fields.unredacted("later", || {
                self.later_accessor_called.set(true);
                "must-not-be-read"
            });
        });
    }
}

/// An argv source that records whether an individual handle operation starts
/// consuming it.
struct ObservedArgvSource(Rc<Cell<bool>>);

impl IntoIterator for ObservedArgvSource {
    type IntoIter = std::vec::IntoIter<ArgvItem<'static>>;
    type Item = ArgvItem<'static>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.set(true);
        vec![ArgvItem::plain(OsStr::new("must-not-be-read"))].into_iter()
    }
}

/// An environment source that exposes whether a process adapter starts
/// consuming the variables after argv traversal has exhausted structure.
struct ObservedEnvSource(Rc<Cell<bool>>);

impl IntoIterator for ObservedEnvSource {
    type IntoIter = std::vec::IntoIter<(&'static OsStr, &'static OsStr)>;
    type Item = (&'static OsStr, &'static OsStr);

    fn into_iter(self) -> Self::IntoIter {
        self.0.set(true);
        vec![(OsStr::new("LATER"), OsStr::new("must-not-be-read"))].into_iter()
    }
}

/// An argv source whose iterator panics after transaction state has become
/// observable, exercising the rollback boundary around a handle operation.
struct PanickingArgvSource;

struct PanickingArgvIter;

impl Iterator for PanickingArgvIter {
    type Item = ArgvItem<'static>;

    fn next(&mut self) -> Option<Self::Item> {
        panic!("test iterator panic");
    }
}

impl ExactSizeIterator for PanickingArgvIter {
    fn len(&self) -> usize {
        1
    }
}

impl IntoIterator for PanickingArgvSource {
    type IntoIter = PanickingArgvIter;
    type Item = ArgvItem<'static>;

    fn into_iter(self) -> Self::IntoIter {
        PanickingArgvIter
    }
}

/// Verifies that `finish()` publishes one transaction and immediately starts a
/// fresh transaction for the same reusable session.
#[test]
fn test_finish_publishes_items_and_resets_the_reusable_session() {
    let redactor = Redactor::standard();
    let mut session = redactor.session();

    let name = session.redact_field("name", "Ada");
    let first = session.finish();

    assert_eq!(
        first
            .resolve(name)
            .expect("handle belongs to first output")
            .text()
            .as_str(),
        "Ada"
    );

    let second = session.literal("next").finish();

    assert_eq!(second.text().as_str(), "next");
    assert_eq!(second.resolve(name), Err(RedactionHandleError::DifferentTransaction));
}

/// Verifies handles cannot resolve against a different session that happens to
/// publish an item at the same local index.
#[test]
fn test_handle_is_rejected_by_a_different_session() {
    let redactor = Redactor::standard();
    let mut first_session = redactor.session();
    let first_handle = first_session.redact_field("first", "Ada");
    let _ = first_session.finish();

    let mut second_session = redactor.session();
    let _ = second_session.redact_field("second", "Grace");
    let second_output = second_session.finish();

    assert_eq!(
        second_output.resolve(first_handle),
        Err(RedactionHandleError::DifferentTransaction)
    );
}

/// Verifies consuming resolution returns the staged output without requiring
/// callers to clone it after transaction publication.
#[test]
fn test_into_resolved_consumes_the_published_session_output() {
    let mut session = Redactor::standard().session();
    let handle = session.redact_field("name", "Ada");

    let resolved = session
        .finish()
        .into_resolved(handle)
        .expect("handle belongs to the completed transaction");

    assert_eq!(resolved.text().as_str(), "Ada");
}

/// Verifies that even an empty committed transaction is a complete published
/// result and that it consumes a transaction identity before the next write.
#[test]
fn test_empty_finish_publishes_complete_output_and_resets_session() {
    let mut session = Redactor::standard().session();

    let empty = session.finish();
    assert!(empty.text().as_str().is_empty());
    assert_eq!(empty.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(empty.summary().usage().output_bytes(), 0);

    let handle = session.redact_field("name", "Ada");
    let next = session.finish();
    assert_eq!(empty.resolve(handle), Err(RedactionHandleError::DifferentTransaction));
    assert_eq!(
        next.resolve(handle)
            .expect("new transaction owns handle")
            .text()
            .as_str(),
        "Ada"
    );
}

/// Verifies that aggregate literal bytes are accounted for by the transaction
/// summary published from the same session state.
#[test]
fn test_literal_output_bytes_are_reported_by_the_published_summary() {
    let mut session = Redactor::standard().session();
    let output = session.literal("safe").finish();

    assert_eq!(output.summary().usage().output_bytes(), 4);
    assert_eq!(output.summary().usage().presented_input_bytes(), 0);
}

/// Verifies that every aggregate write consumes the transaction's one output
/// budget and that an over-budget literal fails closed.
#[test]
fn test_literal_cannot_exceed_the_shared_output_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            let _ = limits.max_output_bytes(4);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();

    let output = session.literal("safe").literal("more").finish();

    assert_eq!(output.text().as_str(), "safe");
    assert_eq!(output.summary().completion(), RedactionCompletion::Exhausted);
    assert_eq!(output.summary().usage().output_bytes(), 4);
}

/// Verifies that argv and environment adapters consume the same structural
/// node and collection-item ledger, rather than allocating one ledger per
/// format operation.
#[test]
fn test_format_adapters_share_the_transaction_structural_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(4).max_collection_items(2);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();

    session.argv(|argv| {
        argv.items([
            ArgvItem::plain(OsStr::new("first")),
            ArgvItem::plain(OsStr::new("second")),
        ]);
    });
    session.env(|env| {
        env.pair("LATER", "must-not-be-rendered");
    });
    let output = session.finish();

    assert!(output.text().as_str().contains("first"));
    assert!(!output.text().as_str().contains("must-not-be-rendered"));
    assert_eq!(output.summary().usage().visited_nodes(), 4);
    assert_eq!(output.summary().usage().visited_collection_items(), 2);
    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
}

/// Verifies process composition does not pre-collect argv or environment
/// sources after its shared structural budget closes.
#[test]
fn test_process_stops_before_consuming_later_format_sources_after_structure_exhaustion() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(2).max_collection_items(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let observed_environment = Rc::new(Cell::new(false));
    let mut session = Redactor::new(policy).session();

    let _ = session.process(|process| {
        let _ = process.command(
            OsStr::new("tool"),
            [ArgvItem::plain(OsStr::new("must-not-be-read"))],
            ObservedEnvSource(Rc::clone(&observed_environment)),
        );
    });
    let output = session.finish();

    assert!(!observed_environment.get());
    assert!(output.text().as_str().is_empty());
    assert_eq!(output.summary().usage().visited_nodes(), 2);
    assert_eq!(output.summary().usage().visited_collection_items(), 1);
    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
}

/// Verifies that the escaped representation, rather than its unescaped source,
/// is charged to the transaction output budget.
#[test]
fn test_literal_escape_bytes_consume_the_shared_output_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            let _ = limits.max_output_bytes(2);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();

    let output = session.literal("a\n").finish();

    assert!(output.text().as_str().is_empty());
    assert_eq!(output.summary().completion(), RedactionCompletion::Exhausted);
    assert_eq!(output.summary().usage().output_bytes(), 0);
}

/// Verifies that aggregate fields are dynamically classified and do not use a
/// keyed-result protocol.
#[test]
fn test_aggregate_fields_use_policy_classification_without_result_keys() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            let _ = fields.secret_sensitive("password");
        })
        .expect("field draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();

    let output = session.field("password", "first").field("password", "second").finish();

    assert!(!output.text().as_str().contains("first"));
    assert!(!output.text().as_str().contains("second"));
    assert_eq!(output.text().as_str(), "<redacted><redacted>");
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}

/// Verifies that a handle result consumes the same output budget as aggregate
/// output and cannot bypass an already exhausted transaction.
#[test]
fn test_handle_result_consumes_the_shared_output_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            let _ = limits.max_output_bytes(4);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();
    let handle = session.redact_field("name", "Alice");
    let output = session.finish();

    let item = output.resolve(handle).expect("handle belongs to output");
    assert!(item.text().as_str().is_empty());
    assert_eq!(item.summary().completion(), RedactionCompletion::Exhausted);
    assert_eq!(output.summary().completion(), RedactionCompletion::Exhausted);
    assert_eq!(output.summary().usage().output_bytes(), 0);
}

/// Verifies that later handle requests reuse one canonical exhausted item
/// instead of growing the transaction item arena after output has closed.
#[test]
fn test_exhausted_handle_requests_reuse_one_published_item() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            let _ = limits.max_output_bytes(0);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();

    let first = session.redact_field("first", "value");
    let second = session.redact_field("second", "value");
    let output = session.finish();

    assert_eq!(first, second);
    let item = output.resolve(first).expect("exhausted handle resolves");
    assert!(item.text().as_str().is_empty());
    assert_eq!(item.summary().completion(), RedactionCompletion::Exhausted);
}

/// Verifies that an unredacted aggregate field is bounded after log escaping,
/// rather than after its source representation has already been retained.
#[test]
fn test_aggregate_field_bounds_the_final_escaped_representation() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            let _ = limits.max_output_bytes(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();

    let output = session.field("message", "\n").field("later", "value").finish();

    assert!(output.text().as_str().is_empty());
    assert_eq!(output.summary().completion(), RedactionCompletion::Exhausted);
    assert_eq!(output.summary().usage().output_bytes(), 0);
    assert_eq!(output.summary().usage().presented_input_bytes(), 8);
    assert_eq!(output.summary().usage().inspected_input_bytes(), 8);
}

/// Verifies that preserved sensitive characters are escaped under the same
/// final-output budget for individually resolved field results.
#[test]
fn test_field_handle_bounds_masked_text_after_log_escaping() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.secret_sensitive("token");
            fields.mask(Sensitivity::Secret, MaskPolicy::preserve_suffix(1, "x", 0));
        })
        .expect("field draft should build")
        .limits(|limits| {
            let _ = limits.max_output_bytes(2);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();

    let handle = session.redact_field("token", "abc\n");
    let output = session.finish();
    let item = output.resolve(handle).expect("handle belongs to output");

    assert!(item.text().as_str().is_empty());
    assert_eq!(item.summary().completion(), RedactionCompletion::Exhausted);
    assert_eq!(output.summary().completion(), RedactionCompletion::Exhausted);
    assert_eq!(output.summary().usage().output_bytes(), 0);
}

/// Verifies that both field entry points admit their complete scalar input
/// through the one session-wide input ledger before classifying or masking it.
#[test]
fn test_field_entry_points_share_input_admission() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            let _ = limits.max_input_bytes(5);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");

    let mut aggregate = Redactor::new(policy.clone()).session();
    let aggregate_output = aggregate.field("name", "xy").finish();
    assert!(aggregate_output.text().as_str().is_empty());
    assert_eq!(aggregate_output.summary().completion(), RedactionCompletion::Truncated);
    assert_eq!(aggregate_output.summary().usage().presented_input_bytes(), 6);
    assert_eq!(aggregate_output.summary().usage().inspected_input_bytes(), 0);

    let mut handles = Redactor::new(policy).session();
    let handle = handles.redact_field("name", "xy");
    let handle_output = handles.finish();
    let item = handle_output.resolve(handle).expect("handle belongs to output");
    assert!(item.text().as_str().is_empty());
    assert_eq!(item.summary().completion(), RedactionCompletion::Truncated);
    assert_eq!(handle_output.summary().usage().presented_input_bytes(), 6);
    assert_eq!(handle_output.summary().usage().inspected_input_bytes(), 0);
}

/// Verifies that a user panic rolls back every prior write in the active
/// transaction, propagates unchanged, and leaves the session reusable.
#[test]
fn test_panic_rolls_back_the_active_transaction_and_resets_the_session() {
    let mut session = Redactor::standard().session();
    let panic = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = session.literal("before").value(&PanicValue);
    }));

    assert!(panic.is_err());
    let output = session.literal("after").finish();
    assert_eq!(output.text().as_str(), "after");
}

/// Verifies panic rollback discards text which a domain writer had appended
/// before it panicked, rather than just resetting a transaction that had no
/// partially rendered state.
#[test]
fn test_panic_after_partial_domain_write_discards_everything() {
    let mut session = Redactor::standard().session();
    let panic = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = session.literal("before").value(&PartiallyWrittenPanicValue);
    }));

    assert!(panic.is_err());
    let output = session.literal("after").finish();
    assert_eq!(output.text().as_str(), "after");
    assert!(!output.text().as_str().contains("before"));
    assert!(!output.text().as_str().contains("must-not-publish"));
}

/// Verifies aggregate adapter closures use the same panic rollback boundary
/// as domain redaction, including writes that preceded the closure.
#[test]
fn test_panicking_adapter_closure_rolls_back_the_active_transaction() {
    let mut session = Redactor::standard().session();
    let panic = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = session.literal("before").argv(|_| panic!("adapter panic"));
    }));

    assert!(panic.is_err());
    assert_eq!(session.literal("after").finish().text().as_str(), "after");
}

/// Verifies an individual domain handle has the same rollback semantics as
/// the aggregate domain operation.
#[test]
fn test_panicking_value_handle_rolls_back_the_active_transaction() {
    let mut session = Redactor::standard().session();
    let panic = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = session.literal("before");
        let _ = session.redact_value(&PanicValue);
    }));

    assert!(panic.is_err());
    assert_eq!(session.literal("after").finish().text().as_str(), "after");
}

/// Verifies an individual adapter handle rolls back when its caller-owned
/// iterator panics while being consumed.
#[test]
fn test_panicking_argv_handle_iterator_rolls_back_the_active_transaction() {
    let mut session = Redactor::standard().session();
    let panic = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = session.literal("before");
        let _ = session.redact_argv(PanickingArgvSource);
    }));

    assert!(panic.is_err());
    assert_eq!(session.literal("after").finish().text().as_str(), "after");
}

/// Verifies that `Redactor::redact` receives its output and summary from a
/// completed session transaction instead of fabricating a completion state.
#[test]
fn test_redactor_redact_uses_the_transaction_output_model() {
    let output = Redactor::standard().redact(&SafeValue);

    assert_eq!(output.text().as_str(), "value");
    assert_eq!(output.summary().usage().output_bytes(), 5);
}

/// Verifies that an individually resolved domain value carries only the
/// usage charged by that value, rather than a fabricated empty summary or a
/// second copy of the transaction's shared traversal charges.
#[test]
fn test_value_handle_keeps_its_operation_summary_without_double_charging() {
    let mut session = Redactor::standard().session();
    let handle = session.redact_value(&SafeValue);
    let output = session.finish();
    let item = output
        .resolve(handle)
        .expect("the value handle belongs to this transaction");

    assert_eq!(item.text().as_str(), "value");
    assert_eq!(item.summary().usage().output_bytes(), 5);
    assert_eq!(output.summary().usage().output_bytes(), 5);
}

/// Verifies that aggregate JSON retains invalid-source provenance in the one
/// transaction summary instead of reducing it to a generic completion.
#[cfg(feature = "json")]
#[test]
fn test_aggregate_json_preserves_invalid_json_provenance() {
    let mut session = Redactor::standard().session();
    let output = session
        .json(|json| {
            json.text("{not valid json");
        })
        .finish();

    assert!(output.summary().reasons().contains(RedactionReason::InvalidJson));
}

/// Verifies that aggregate URI redaction retains invalid-source provenance in
/// the shared transaction summary.
#[cfg(feature = "uri")]
#[test]
fn test_aggregate_uri_preserves_invalid_uri_provenance() {
    let mut session = Redactor::standard().session();
    let output = session
        .uri(|uri| {
            uri.value("not a uri");
        })
        .finish();

    assert!(output.summary().reasons().contains(RedactionReason::InvalidUri));
}

/// Verifies that HTTP URL redaction preserves invalid-URI provenance through
/// the aggregate transaction path.
#[cfg(feature = "http")]
#[test]
fn test_aggregate_http_url_preserves_invalid_uri_provenance() {
    let mut session = Redactor::standard().session();
    let output = session
        .http(|http| {
            http.url("not a url");
        })
        .finish();

    assert!(output.summary().reasons().contains(RedactionReason::InvalidUri));
}

/// Verifies that trait convenience methods select the application default or
/// an explicit redactor instead of constructing a separate lazy view.
#[test]
fn test_redact_trait_convenience_methods_use_redactors() {
    let output = SafeValue.redacted();
    assert_eq!(output.text().as_str(), "value");

    let explicit = Redactor::strict();
    let output = SafeValue.redacted_with(&explicit);
    assert_eq!(output.text().as_str(), "value");
}

/// Verifies the writer gives unredacted fields an unmistakable API name while
/// fixed secret sensitivity avoids executing the source accessor.
#[test]
fn test_writer_unredacted_and_fixed_sensitive_fields_have_distinct_contracts() {
    let output = Redactor::standard().redact(&WriterContractValue);

    assert!(output.text().as_str().contains("id: 7"));
    assert!(!output.text().as_str().contains("token accessor"));
    assert!(output.text().as_str().contains("<redacted>"));
}

/// Verifies the runtime policy can raise an explicitly low field, while an
/// explicit high floor cannot be lowered by a weaker runtime classification.
#[test]
fn test_writer_sensitive_merges_explicit_and_runtime_minimums_before_access() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            let _ = fields.secret_sensitive("runtime_secret");
            let _ = fields.low_sensitive("explicit_high");
        })
        .expect("field configuration should build")
        .build()
        .expect("policy should build");

    let output = Redactor::new(policy).redact(&RuntimeSensitiveWriterContractValue);

    assert!(!output.text().as_str().contains("accessor must not run"));
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}

/// Verifies a sensitivity below the opaque-access cutoff evaluates its source
/// exactly once and renders through the bounded masking path.
#[test]
fn test_writer_low_sensitivity_evaluates_and_masks_the_source() {
    let accessed = Rc::new(Cell::new(false));
    let value = WriterLowSensitivityValue {
        accessed: Rc::clone(&accessed),
    };
    let output = Redactor::standard().redact(&value);

    assert!(accessed.get());
    assert!(output.text().as_str().contains("note:"));
    assert!(!output.text().as_str().contains("visible note"));
    assert!(output.text().as_str().contains("****"));
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}

/// Verifies every structured-writer shape remains inside the single parent
/// transaction.
#[test]
fn test_writer_structured_shapes_share_the_parent_transaction() {
    let shapes = WriterShapesValue;
    let mut session = Redactor::standard().session();

    let output = session.value(&shapes).value(&WriterTupleValue).finish();

    assert!(output.text().as_str().contains("[Leaf, Leaf]"));
    assert!(output.text().as_str().contains("leaf: Leaf"));
    assert!(output.text().as_str().contains("Pair(Leaf, Leaf)"));
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(output.summary().usage().output_bytes(), output.text().as_str().len());
}

/// Verifies the domain writer receives the transaction's remaining output
/// capacity and reports truncation instead of bypassing it.
#[test]
fn test_writer_uses_the_transaction_output_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            let _ = limits.max_output_bytes(12);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");

    let output = Redactor::new(policy).redact(&WriterLargeValue);

    assert!(output.text().as_str().len() <= 12);
    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
    assert_eq!(output.summary().usage().output_bytes(), output.text().as_str().len());
}

/// A writer's real output overflow must remain visible even when an earlier
/// operation has already recorded a distinct transaction-wide truncation.
#[test]
fn test_writer_output_limit_provenance_accumulates_after_input_limit() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            let _ = limits.max_input_bytes(1);
            let _ = limits.max_output_bytes(12);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();

    let output = session.field("name", "x").value(&WriterLargeValue).finish();

    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
    assert!(output.summary().reasons().contains(RedactionReason::InputLimitReached));
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
}

/// Individually resolved writer output retains its own output-limit reason
/// after an earlier transaction-wide input-limit truncation.
#[test]
fn test_writer_handle_output_limit_provenance_accumulates_after_input_limit() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            let _ = limits.max_input_bytes(1);
            let _ = limits.max_output_bytes(12);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();

    let _ = session.field("name", "x");
    let handle = session.redact_value(&WriterLargeValue);
    let output = session.finish();
    let item = output.resolve(handle).expect("handle should resolve");

    assert!(item.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert!(output.summary().reasons().contains(RedactionReason::InputLimitReached));
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
}

/// Repeated truncation reasons belong to every handle operation that causes
/// them, even when the transaction had already recorded the same reason.
#[test]
fn test_each_handle_keeps_a_repeated_traversal_limit_reason() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(0);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();

    let first = session.redact_value(&WriterTupleValue);
    let second = session.redact_value(&WriterTupleValue);
    let output = session.finish();

    for handle in [first, second] {
        let item = output.resolve(handle).expect("handle should resolve");
        assert_eq!(item.summary().completion(), RedactionCompletion::Truncated);
        assert!(
            item.summary()
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
    }
}

/// An item reports the depth observed by that operation rather than the
/// greatest depth reached by an earlier operation in the transaction.
#[test]
fn test_handle_max_depth_is_local_to_its_operation() {
    let shapes = WriterShapesValue;
    let mut session = Redactor::standard().session();

    let _ = session.value(&shapes);
    let handle = session.redact_value(&SafeValue);
    let output = session.finish();
    let item = output.resolve(handle).expect("handle should resolve");

    assert!(output.summary().usage().max_depth() > 0);
    assert_eq!(item.summary().usage().max_depth(), 0);
}

/// Input admission failure is attributed to the rejected handle rather than
/// being mislabeled as an output or traversal failure.
#[test]
fn test_rejected_field_handle_reports_its_input_limit_usage() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();

    let handle = session.redact_field("name", "Ada");
    let output = session.finish();
    let item = output.resolve(handle).expect("handle should resolve");

    assert_eq!(item.summary().completion(), RedactionCompletion::Truncated);
    assert!(item.summary().reasons().contains(RedactionReason::InputLimitReached));
    assert!(
        !item
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
    assert!(!item.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert_eq!(item.summary().usage().presented_input_bytes(), 7);
    assert_eq!(item.summary().usage().inspected_input_bytes(), 0);
    assert_eq!(item.summary().usage().omitted_input_bytes(), Some(7));
}

/// A writer must stop the current `Debug` formatter at the shared output
/// ceiling and must not inspect later field accessors after that ceiling.
#[test]
fn test_writer_stops_formatting_and_later_accessors_at_output_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            let _ = limits.max_output_bytes(32);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let debug_continued = Rc::new(Cell::new(false));
    let later_accessor_called = Rc::new(Cell::new(false));
    let value = WriterBudgetStopValue {
        debug_value: DebugStopsAtBudget {
            visited_after_first_chunk: Rc::clone(&debug_continued),
        },
        later_accessor_called: Rc::clone(&later_accessor_called),
    };

    let output = Redactor::new(policy).redact(&value);

    assert!(!debug_continued.get());
    assert!(!later_accessor_called.get());
    assert!(output.text().as_str().len() <= 32);
    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
}

/// Verifies a format namespace appends through the same transaction buffer as
/// literals instead of publishing an independent keyed result.
#[test]
fn test_argv_namespace_appends_to_the_shared_aggregate_output() {
    let mut session = Redactor::standard().session();

    let output = session
        .literal("argv=")
        .argv(|argv| {
            argv.items([ArgvItem::plain(OsStr::new("client"))]);
        })
        .finish();

    assert_eq!(output.text().as_str(), "argv=[\"client\"]");
    assert_eq!(output.summary().usage().output_bytes(), output.text().as_str().len());
}

/// Verifies each aggregate format namespace borrows the same live
/// transaction, rather than creating an independent result or budget.
#[test]
#[cfg(all(feature = "json", feature = "http", feature = "uri"))]
fn test_all_format_namespaces_append_to_one_transaction() {
    let mut session = Redactor::standard().session();

    let output = session
        .literal("literal=")
        .field("label", "field")
        .value(&SafeValue)
        .json(|json| {
            json.text(r#"{"json":"visible"}"#);
        })
        .http(|http| {
            http.url("https://example.test/path?label=visible");
            let _ = http.body(BodyCapture::complete(br#"{"body":"visible"}"#), None);
        })
        .uri(|uri| {
            uri.value("https://example.test/path?label=visible");
        })
        .argv(|argv| {
            argv.items([ArgvItem::plain(OsStr::new("client"))]);
        })
        .env(|env| {
            env.pair("LABEL", "visible");
        })
        .process(|process| {
            process.command(
                OsStr::new("tool"),
                [ArgvItem::plain(OsStr::new("--verbose"))],
                [(OsStr::new("MODE"), OsStr::new("test"))],
            );
        })
        .finish();

    assert!(output.text().as_str().contains("literal=fieldvalue"));
    assert!(output.text().as_str().contains("json"), "{}", output.text().as_str());
    assert!(output.text().as_str().contains("body"), "{}", output.text().as_str());
    assert!(output.text().as_str().contains("example.test"));
    assert!(output.text().as_str().contains("client"));
    assert!(output.text().as_str().contains("LABEL"));
    assert!(output.text().as_str().contains("tool"));
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}

/// Verifies that every later format closure is skipped after one transaction
/// has exhausted its shared output budget.
#[test]
#[cfg(all(feature = "json", feature = "http", feature = "uri"))]
fn test_all_format_namespaces_skip_after_output_exhaustion() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();

    let output = session
        .literal("too-large")
        .field("label", "must-not-be-read")
        .value(&PanicValue)
        .json(|_| panic!("JSON closure must not run"))
        .http(|_| panic!("HTTP closure must not run"))
        .uri(|_| panic!("URI closure must not run"))
        .argv(|_| panic!("argv closure must not run"))
        .env(|_| panic!("env closure must not run"))
        .process(|_| panic!("process closure must not run"))
        .finish();

    assert_eq!(output.text().as_str(), "");
    assert_eq!(output.summary().completion(), RedactionCompletion::Exhausted);
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
}

/// Verifies every non-HTTP format has both a session handle operation and a
/// one-shot `Redactor` convenience operation backed by that same transaction
/// path.
#[test]
fn test_format_handle_and_redactor_convenience_operations_publish_transaction_output() {
    use std::ffi::OsStr;

    let redactor = Redactor::strict();

    let argv = redactor.redact_argv([ArgvItem::plain(OsStr::new("client"))]);
    assert_eq!(argv.text().as_str(), "[\"client\"]");

    let env = redactor.redact_env("PASSWORD", "env-secret");
    assert!(!env.text().as_str().contains("env-secret"));

    let process = redactor.redact_process(
        OsStr::new("client"),
        [
            ArgvItem::plain(OsStr::new("--password")),
            ArgvItem::plain(OsStr::new("argv-secret")),
        ],
        [(OsStr::new("PASSWORD"), OsStr::new("process-secret"))],
    );
    assert!(!process.text().as_str().contains("argv-secret"));
    assert!(!process.text().as_str().contains("process-secret"));

    #[cfg(feature = "json")]
    {
        let json = redactor.redact_json(r#"{"password":"json-secret"}"#);
        assert!(!json.text().as_str().contains("json-secret"));
    }

    #[cfg(feature = "uri")]
    {
        let uri = redactor.redact_uri("https://example.test/path?token=uri-secret");
        assert!(!uri.text().as_str().contains("uri-secret"));
    }

    let mut session = redactor.session();
    let handle = session.redact_env("PASSWORD", "session-secret");
    let output = session.finish();
    assert!(
        !output
            .resolve(handle)
            .expect("session handle must resolve")
            .text()
            .as_str()
            .contains("session-secret")
    );
}

/// A process handle is one staged transaction item: its argv and environment
/// portions share the caller's policy, but it is not aggregate output until
/// the parent transaction commits.
#[test]
fn test_process_handle_publishes_one_safe_combined_item_after_finish() {
    let mut session = Redactor::strict().session();
    let handle = session.redact_process(
        OsStr::new("client"),
        [
            ArgvItem::plain(OsStr::new("--password")),
            ArgvItem::plain(OsStr::new("argv-secret")),
        ],
        [(OsStr::new("PASSWORD"), OsStr::new("env-secret"))],
    );
    let output = session.finish();
    let item = output.resolve(handle).expect("process handle publishes at finish");

    assert!(output.text().as_str().is_empty());
    assert!(item.text().as_str().contains("client"));
    assert!(!item.text().as_str().contains("argv-secret"));
    assert!(!item.text().as_str().contains("env-secret"));
    assert_eq!(item.summary().completion(), RedactionCompletion::Complete);
}

/// A process handle observes the shared output ledger before it invokes argv
/// or environment rendering, so an exhausted transaction publishes an empty
/// fail-closed item instead of a second process-specific result.
#[test]
fn test_process_handle_observes_parent_output_exhaustion() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            let _ = limits.max_output_bytes(3);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();
    let _ = session.literal("pre");
    let handle = session.redact_process(
        OsStr::new("client"),
        [ArgvItem::plain(OsStr::new("--password"))],
        [(OsStr::new("PASSWORD"), OsStr::new("must-not-be-rendered"))],
    );
    let output = session.finish();
    let item = output
        .resolve(handle)
        .expect("exhausted process handle belongs to transaction");

    assert_eq!(output.text().as_str(), "pre");
    assert!(item.text().as_str().is_empty());
    assert_eq!(item.summary().completion(), RedactionCompletion::Exhausted);
}

/// Verifies a process handle created after aggregate argv rendering closes the
/// shared output budget publishes an exhausted item from the same transaction.
#[test]
fn test_process_handle_inside_namespace_observes_prior_aggregate_exhaustion() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            let _ = limits.max_output_bytes(5);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();
    let mut handle = None;

    let _ = session.process(|process| {
        process.arguments([ArgvItem::plain(OsStr::new("a"))]);
        handle = Some(process.redact_command(
            OsStr::new("client"),
            Vec::<ArgvItem<'_>>::new(),
            Vec::<(&OsStr, &OsStr)>::new(),
        ));
    });
    let output = session.finish();
    let item = output
        .resolve(handle.expect("process namespace must produce a handle"))
        .expect("completed transaction must resolve its process handle");

    assert_eq!(output.text().as_str(), "[\"a\"]");
    assert!(item.text().as_str().is_empty());
    assert_eq!(item.summary().completion(), RedactionCompletion::Exhausted);
}

/// The process facade's separate argv and environment methods are aggregate
/// aliases over the same transaction, preserving heuristic masking for argv
/// and field-policy masking for environment values.
#[test]
fn test_process_arguments_and_variables_share_one_safe_aggregate_output() {
    let mut session = Redactor::strict().session();
    let _ = session.process(|process| {
        process
            .arguments([
                ArgvItem::plain(OsStr::new("--token")),
                ArgvItem::plain(OsStr::new("argv-secret")),
            ])
            .variables([(OsStr::new("PASSWORD"), OsStr::new("env-secret"))]);
    });
    let output = session.finish();

    assert!(output.text().as_str().contains("--token"));
    assert!(output.text().as_str().contains("PASSWORD"));
    assert!(!output.text().as_str().contains("argv-secret"));
    assert!(!output.text().as_str().contains("env-secret"));
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}

/// Verifies all aggregate process facade operations append through the public
/// namespace closure and preserve one parent transaction.
#[test]
fn test_process_facade_command_arguments_and_variables_append_to_one_transaction() {
    let mut session = Redactor::strict().session();
    let _ = session.process(|process| {
        process
            .command(
                OsStr::new("client"),
                [
                    ArgvItem::plain(OsStr::new("--password")),
                    ArgvItem::plain(OsStr::new("command-secret")),
                ],
                [(OsStr::new("COMMAND_TOKEN"), OsStr::new("environment-secret"))],
            )
            .arguments([
                ArgvItem::plain(OsStr::new("--token")),
                ArgvItem::plain(OsStr::new("argument-secret")),
            ])
            .variables([(OsStr::new("PASSWORD"), OsStr::new("variable-secret"))]);
    });
    let output = session.finish();
    let rendered = output.text().as_str();

    assert!(rendered.contains("client"));
    assert!(rendered.contains("COMMAND_TOKEN"));
    assert!(rendered.contains("PASSWORD"));
    assert!(!rendered.contains("command-secret"));
    assert!(!rendered.contains("environment-secret"));
    assert!(!rendered.contains("argument-secret"));
    assert!(!rendered.contains("variable-secret"));
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}

/// Verifies an empty command and empty environment remain a valid complete
/// individually resolvable process item through the public session facade.
#[test]
fn test_process_handle_accepts_empty_vec_inputs() {
    let mut session = Redactor::standard().session();
    let handle = session.redact_process(
        OsStr::new("client"),
        Vec::<ArgvItem<'_>>::new(),
        Vec::<(&OsStr, &OsStr)>::new(),
    );
    let output = session.finish();
    let item = output
        .resolve(handle)
        .expect("the completed transaction must resolve its process handle");

    assert_eq!(item.text().as_str(), "[\"client\"][]");
    assert_eq!(item.summary().completion(), RedactionCompletion::Complete);
}

/// Verifies a closed output budget prevents an adapter closure from running.
#[test]
fn test_exhausted_output_does_not_invoke_later_adapter_closures() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            let _ = limits.max_output_bytes(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();

    let output = session
        .literal("too long")
        .argv(|_| panic!("an exhausted session must not invoke the adapter"))
        .finish();

    assert!(output.text().as_str().is_empty());
    assert_eq!(output.summary().completion(), RedactionCompletion::Exhausted);
}

/// Verifies an exhausted transaction does not even start a caller-owned
/// iterator passed to an individual adapter-handle API.
#[test]
fn test_exhausted_output_does_not_consume_later_handle_iterators() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            let _ = limits.max_output_bytes(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let attempted = Rc::new(Cell::new(false));
    let mut session = Redactor::new(policy).session();

    let _ = session.literal("x");
    let handle = session.redact_argv(ObservedArgvSource(Rc::clone(&attempted)));
    let value = session.redact_value(&PanicValue);
    let output = session.finish();

    assert!(!attempted.get());
    assert_eq!(
        output
            .resolve(handle)
            .expect("exhausted handle remains resolvable")
            .summary()
            .completion(),
        RedactionCompletion::Exhausted
    );
    assert_eq!(
        output
            .resolve(value)
            .expect("exhausted handle remains resolvable")
            .summary()
            .completion(),
        RedactionCompletion::Exhausted
    );
}

/// Verifies a format limits parsing to the admitted input prefix and reports
/// the presented and inspected byte counts separately.
#[cfg(feature = "json")]
#[test]
fn test_json_input_budget_admits_the_parser_prefix() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            let _ = limits.max_input_bytes(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();

    let output = session
        .json(|json| {
            json.text("{invalid json");
        })
        .finish();

    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
    assert!(output.summary().reasons().contains(RedactionReason::InputLimitReached));
    assert_eq!(output.summary().usage().presented_input_bytes(), "{invalid json".len());
    assert_eq!(output.summary().usage().inspected_input_bytes(), 1);
}

/// Verifies a format handle remains separate from aggregate text until its
/// completed transaction output resolves it.
#[cfg(feature = "uri")]
#[test]
fn test_uri_handle_is_resolved_only_from_the_completed_transaction() {
    let mut session = Redactor::standard().session();
    let uri = session.redact_uri("https://example.test/path?token=raw");
    let output = session.literal("aggregate").finish();

    assert_eq!(output.text().as_str(), "aggregate");
    assert!(
        output
            .resolve(uri)
            .expect("URI handle belongs to output")
            .text()
            .as_str()
            .contains("example.test")
    );
}

/// A zero-sized output budget must be published as exhaustion even when the
/// first aggregate operation is skipped before it can inspect its input.
#[test]
fn test_zero_output_budget_marks_skipped_aggregate_field_as_exhausted() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            let _ = limits.max_output_bytes(0);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();

    let output = session.field("password", "secret").finish();

    assert!(output.text().as_str().is_empty());
    assert_eq!(output.summary().completion(), RedactionCompletion::Exhausted);
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert_eq!(output.summary().usage().presented_input_bytes(), 0);
}

/// A recovered transaction must invalidate handles created before the panic.
#[test]
fn test_panic_rollback_invalidates_handles_from_the_discarded_transaction() {
    let mut session = Redactor::standard().session();
    let discarded = session.redact_field("before", "discarded");
    let panic = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = session.value(&PanicValue);
    }));
    assert!(panic.is_err());

    let retained = session.redact_field("after", "retained");
    let output = session.finish();

    assert_eq!(
        output.resolve(discarded),
        Err(RedactionHandleError::DifferentTransaction)
    );
    assert_eq!(
        output
            .resolve(retained)
            .expect("fresh handle belongs to output")
            .text()
            .as_str(),
        "retained"
    );
}

/// Chained and statement-style aggregate calls have identical publication
/// semantics.
#[test]
fn test_chain_and_statement_aggregate_calls_are_equivalent() {
    let mut chained = Redactor::standard().session();
    let chained_output = chained.field("name", "Ada").literal("!").finish();

    let mut statements = Redactor::standard().session();
    let _ = statements.field("name", "Ada");
    let _ = statements.literal("!");
    let statement_output = statements.finish();

    assert_eq!(chained_output.text(), statement_output.text());
    assert_eq!(chained_output.summary(), statement_output.summary());
}

/// Reusing a session repeatedly publishes only the current transaction.
#[test]
fn test_three_consecutive_finishes_publish_independent_transactions() {
    let mut session = Redactor::standard().session();

    let first = session.literal("one").finish();
    let second = session.literal("two").finish();
    let third = session.literal("three").finish();

    assert_eq!(first.text().as_str(), "one");
    assert_eq!(second.text().as_str(), "two");
    assert_eq!(third.text().as_str(), "three");
}
