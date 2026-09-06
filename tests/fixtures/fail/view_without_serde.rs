use qubit_redact::Redactor;
use qubit_redact_derive::Redact as DeriveRedact;

#[derive(DeriveRedact)]
struct Plain {
    value: String,
}

fn main() {
    let value = Plain {
        value: "visible".to_owned(),
    };
    let _ = serde_json::to_string(&Redactor::standard().redact_view(&value));
}
