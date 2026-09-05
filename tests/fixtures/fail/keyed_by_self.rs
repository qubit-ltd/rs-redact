use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Pair {
    #[redact(keyed_by = value)]
    value: String,
}

fn main() {}
