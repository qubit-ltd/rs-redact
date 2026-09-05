use qubit_redact::Redact as RedactTrait;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Record {
    visible: String,
    #[redact(level = "secret")]
    password: String,
    #[redact(skip)]
    omitted: String,
}

fn main() {
    let value = Record {
        visible: "shown".into(),
        password: "raw-secret".into(),
        omitted: "restored".into(),
    };
    let output = Redactor::standard().redact(&value);
    assert!(output.text().as_str().contains("shown"));
    assert!(!output.text().as_str().contains("raw-secret"));
    assert!(!output.text().as_str().contains("restored"));
}

struct Child;

impl RedactTrait for Child {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Child", |fields| {
            fields.sensitive(Sensitivity::Secret, "token", || "raw");
        });
    }
}
