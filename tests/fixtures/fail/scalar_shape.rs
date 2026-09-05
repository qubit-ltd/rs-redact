use qubit_redact::RedactScalar;
#[derive(RedactScalar)]
struct Empty;
#[derive(RedactScalar)]
struct Pair(u64, u64);
#[derive(RedactScalar)]
enum Choice { Item(u64) }
#[derive(RedactScalar)]
struct Collection(Vec<u64>);
#[derive(RedactScalar)]
struct Classified(#[redact(level = "secret")] String);
fn main() {}
