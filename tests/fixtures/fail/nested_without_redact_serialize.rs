use qubit_redact::Redact as RedactTrait;
use qubit_redact::RedactionWriter;
use qubit_redact_derive::Redact;

struct Child;

impl RedactTrait for Child {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.literal("Child");
    }
}

#[derive(Redact)]
#[redact(serde)]
struct Bad {
    #[redact(nested)]
    child: Child,
}

fn main() {}
