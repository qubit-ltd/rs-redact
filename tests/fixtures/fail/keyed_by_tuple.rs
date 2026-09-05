use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Pair(String, #[redact(keyed_by = key)] String);

fn main() {}
