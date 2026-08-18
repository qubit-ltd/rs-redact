#![no_main]

use libfuzzer_sys::fuzz_target;
use qubit_redact::Redactor;

fuzz_target!(|input: &[u8]| {
    let text = String::from_utf8_lossy(input);
    let redactor = Redactor::standard();

    let url = redactor.http().redact_url_str(&text);
    assert!(!url.as_str().contains("fuzz-secret"));
    let uri = redactor.uri().redact_uri_str(&text);
    assert!(!uri.text().as_str().contains("fuzz-secret"));
});
