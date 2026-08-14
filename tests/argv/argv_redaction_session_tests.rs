use std::cell::Cell;
use std::ffi::OsStr;

use qubit_redact::InputOutputLimit;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::argv::ArgvItem;

struct CountingItems<'count> {
    pulls: &'count Cell<usize>,
}

impl Iterator for CountingItems<'_> {
    type Item = ArgvItem<'static>;

    fn next(&mut self) -> Option<Self::Item> {
        self.pulls.set(self.pulls.get() + 1);
        Some(ArgvItem::plain(OsStr::new("unread-secret")))
    }
}

/// Verifies that a terminal session does not pull a second iterator item.
#[test]
fn test_argv_session_does_not_pull_iterator_after_output_exhaustion() {
    let limit = InputOutputLimit::new(1, InputOutputLimit::MIN_OUTPUT_BYTES)
        .expect("the marker-sized diagnostic limit should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(limit)
        .build()
        .expect("the test policy should build");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();
    let pulls = Cell::new(0);
    let _ = session
        .argv()
        .redact_heuristically(CountingItems { pulls: &pulls });
    let pulls_after_exhaustion = pulls.get();
    let _ = session
        .argv()
        .redact_heuristically(CountingItems { pulls: &pulls });
    assert_eq!(pulls.get(), pulls_after_exhaustion);
}

/// Verifies list delimiters are included in shared output accounting.
#[test]
fn test_argv_session_charges_delimiters_across_following_operations() {
    let limit = InputOutputLimit::new(128, 64)
        .expect("the diagnostic limit should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(limit)
        .build()
        .expect("the test policy should build");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();
    let argv = session
        .argv()
        .redact_items([ArgvItem::plain(OsStr::new("client"))])
        .to_string();
    let env = session.env().redact_pair("MODE", "debug").to_string();

    assert_eq!(
        session.remaining_output_bytes(),
        limit.max_output_bytes() - argv.len() - env.len()
    );
}
