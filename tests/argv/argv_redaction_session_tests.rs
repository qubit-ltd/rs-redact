use std::ffi::OsStr;

use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::formats::argv::ArgvItem;

#[test]
fn session_publishes_argv_handle_only_after_finish() {
    let mut session = Redactor::standard().session();
    let handle = session.redact_argv([ArgvItem::plain(OsStr::new("client"))]);
    let output = session.finish();

    assert_eq!(
        output.resolve(handle).expect("published handle").text().as_str(),
        r#"["client"]"#
    );
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}

#[test]
fn aggregate_argv_adapters_append_to_the_same_output() {
    let mut session = Redactor::standard().session();
    session.argv(|argv| {
        argv.items([ArgvItem::plain(OsStr::new("client"))]);
    });
    session.argv(|argv| {
        argv.items([ArgvItem::plain(OsStr::new("worker"))]);
    });
    let output = session.finish();

    assert!(output.text().as_str().contains("client"));
    assert!(output.text().as_str().contains("worker"));
}

/// Heuristic argv rendering must keep the option-value contract while using
/// the same transaction-owned output allowance as surrounding adapters.
#[test]
fn heuristic_argv_masks_pending_secret_value_in_aggregate_transaction() {
    let mut session = Redactor::strict().session();
    session.argv(|argv| {
        argv.heuristic_items([
            ArgvItem::plain(OsStr::new("--password")),
            ArgvItem::plain(OsStr::new("argv-secret")),
        ]);
    });
    let output = session.finish();

    assert!(output.text().as_str().contains("--password"));
    assert!(!output.text().as_str().contains("argv-secret"));
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}

/// Collection admission must stop argv traversal before a later secret item
/// can reach the renderer, and the handle must retain the transaction result.
#[test]
fn argv_handle_stops_at_shared_collection_limit() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();
    let handle = session.redact_argv([
        ArgvItem::plain(OsStr::new("first")),
        ArgvItem::plain(OsStr::new("later-secret")),
    ]);
    let output = session.finish();
    let item = output.resolve(handle).expect("truncated argv handle publishes");

    assert!(item.text().as_str().is_empty());
    assert_eq!(item.summary().completion(), RedactionCompletion::Truncated);
    assert!(!item.text().as_str().contains("later-secret"));
}
