use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Record {
    #[redact(level = "secret")]
    values: Option<Vec<[(u32, String); 1]>>,
}

fn main() {
    let _ = Record {
        values: Some(vec![[(7, "raw".to_owned())]]),
    };
}
