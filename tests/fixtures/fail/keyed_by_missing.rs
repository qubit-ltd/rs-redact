use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Pair {
    key: String,
    #[redact(keyed_by = missing)]
    value: String,
}

fn main() {}
