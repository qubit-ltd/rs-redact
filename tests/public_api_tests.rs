//! Public transactional API surface checks.

use qubit_redact::Redact;
use qubit_redact::RedactedText;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionHandle;
use qubit_redact::RedactionHandleError;
use qubit_redact::RedactionOutput;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionSession;
use qubit_redact::RedactionSessionOutput;
use qubit_redact::RedactionSummary;
use qubit_redact::RedactionUsage;
use qubit_redact::Redactor;

/// Proves the target public types are available through the crate root.
#[test]
fn target_transactional_types_are_public() {
    fn assert_redact<T: Redact + ?Sized>() {}
    let _ = assert_redact::<PublicApiValue>;
    let _: Option<RedactedText> = None;
    let _: Option<RedactionCompletion> = None;
    let _: Option<RedactionHandle> = None;
    let _: Option<RedactionHandleError> = None;
    let _: Option<RedactionOutput> = None;
    let _: Option<RedactionPolicy> = None;
    let _: Option<RedactionSession> = None;
    let _: Option<RedactionSessionOutput> = None;
    let _: Option<RedactionSummary> = None;
    let _: Option<RedactionUsage> = None;
    let _: Option<Redactor> = None;
}

/// Minimal type used only to prove the public trait is implementable.
struct PublicApiValue;

impl Redact for PublicApiValue {}
