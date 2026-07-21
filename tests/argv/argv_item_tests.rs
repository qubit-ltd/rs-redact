use std::ffi::OsStr;

use qubit_redact::{
    ArgvRedactor,
    argv::ArgvItem,
};

/// Verifies that plain argument items are rendered unchanged by explicit mode.
#[test]
fn test_argv_item_plain_is_rendered_without_masking() {
    let rendered = ArgvRedactor::default()
        .redact_items([ArgvItem::plain(OsStr::new("client"))])
        .to_string();

    assert_eq!(rendered, r#"["client"]"#);
}
