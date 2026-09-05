use qubit_redact_derive::Redact;

fn serialize_value<S>(value: &String, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(value)
}

#[derive(Redact)]
#[redact(serde)]
struct Bad {
    #[redact(level = "secret")]
    #[serde(serialize_with = "serialize_value")]
    value: String,
}

fn main() {}
