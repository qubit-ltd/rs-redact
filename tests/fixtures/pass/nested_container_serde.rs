use qubit_redact_derive::Redact;

#[derive(Redact)]
#[redact(serde)]
struct Child {
    #[redact(level = "secret")]
    token: String,
}

#[derive(Redact)]
#[redact(serde)]
struct Parent {
    #[redact(nested)]
    children: Option<Vec<Child>>,
}

fn main() {
    let value = Parent {
        children: Some(vec![Child { token: "raw".to_owned() }]),
    };
    let _ = serde_json::to_value(value).unwrap();
}
