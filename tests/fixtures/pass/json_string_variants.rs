use std::borrow::Cow;

use qubit_redact_derive::Redact;

#[derive(Redact)]
#[redact(serde)]
struct JsonStrings<'a> {
    #[redact(json)]
    owned: String,
    #[redact(json)]
    borrowed: &'a str,
    #[redact(json)]
    cow: Cow<'a, str>,
    #[redact(json)]
    optional: Option<Cow<'a, str>>,
}

fn main() {
    let _ = JsonStrings {
        owned: "{}".to_owned(),
        borrowed: "{}",
        cow: Cow::Borrowed("{}"),
        optional: None,
    };
}
