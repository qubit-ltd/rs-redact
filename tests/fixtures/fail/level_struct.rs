use qubit_redact_derive::Redact;

#[derive(Debug)]
struct Child;

#[derive(Redact)]
struct Bad {
    #[redact(level = "secret")]
    child: Child,
}

fn main() {}
