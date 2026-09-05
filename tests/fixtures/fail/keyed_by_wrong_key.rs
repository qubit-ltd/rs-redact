use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Pair {
    key: u32,
    #[redact(keyed_by = key)]
    value: String,
}

fn main() {}
