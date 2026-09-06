use qubit_redact::Redact;
#[derive(Redact)]
struct Missing {
    #[redact(display)]
    value: String,
}
#[derive(Redact)]
struct Conflicting {
    #[redact(nested, display)]
    value: String,
}
#[derive(Redact)]
struct Duplicate {
    #[redact(level = "secret", display, display)]
    value: String,
}
#[derive(Redact)]
#[redact(serialize)]
struct Removed {
    value: String,
}
fn main() {}
