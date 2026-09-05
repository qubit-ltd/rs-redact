use qubit_redact::Redact;

#[derive(Redact)]
#[redact(no_mut)]
struct RemovedContainerAttribute {
    #[redact(plain)]
    value: String,
}

fn main() {}
