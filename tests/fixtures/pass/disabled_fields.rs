use qubit_redact_derive::Redact;

#[derive(Redact)]
#[redact(serde)]
struct Record {
    #[redact(level = "secret")]
    number: u32,
    #[redact(skip)]
    restored_when_disabled: String,
}

fn main() {
    let _ = Record {
        number: 7,
        restored_when_disabled: "raw".to_owned(),
    };
}
