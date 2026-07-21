use std::ffi::OsStr;

use qubit_redact::ArgvRedactor;
use qubit_redact::argv::ArgvItem;

/// Verifies that the argv redactor masks a heuristic password value.
#[test]
fn test_argv_redactor_masks_password_value() {
    let rendered = ArgvRedactor::default()
        .redact_heuristically([
            ArgvItem::plain(OsStr::new("--password")),
            ArgvItem::plain(OsStr::new("raw")),
        ])
        .to_string();
    assert!(!rendered.contains("raw"));
}
