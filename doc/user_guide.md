# qubit-redact User Guide

[README](../README.md) · [中文用户手册](user_guide.zh_CN.md) · [Derive Guide](https://github.com/qubit-ltd/rs-redact-derive/blob/main/doc/user_guide.md)

`qubit-redact` creates bounded, policy-aware output without changing the source
value. A `Redactor` owns the policy snapshot; a redaction operation owns the
final `RedactedText`.

## 1. Render a domain value

Implement the small runtime trait, or derive it in a downstream crate:

```rust
use qubit_redact::{Redact, RedactionWriter, Redactor, Sensitivity};

struct Login { user: String, password: String }

impl Redact for Login {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Login", |fields| {
            fields.unmarked("user", || self.user.as_str());
            fields.sensitive(Sensitivity::Secret, "password", || self.password.as_str());
        });
    }
}

let login = Login { user: "ada".into(), password: "raw".into() };
let output = Redactor::standard().redact(&login);
assert!(!output.text().as_str().contains("raw"));
assert_eq!(login.password, "raw");
```

Use `Redactor::new(policy)` when a subsystem needs an explicit policy. The
runtime has no mutable redaction API and does not provide memory zeroization.

## 2. Writer scopes

`RedactionWriter` exposes explicit field decisions:

- `unmarked(name, access)` renders a reviewed ordinary value;
- `sensitive(level, name, access)` applies a sensitivity mask;
- `nested(name, value)` delegates to another `Redact` implementation;
- `map(name, value)` applies key-aware handling to supported maps;
- `json(name, value)` applies recursive JSON handling;
- `skipped(name, access)` omits a field without rendering its value.

Each operation participates in the same output budget and summary. A field
that may contain sensitive data must not be left unmarked merely because the
current policy happens to mask it elsewhere.

## 3. Other formats

The runtime provides bounded redaction for JSON text and values, URI, HTTP
headers/query data, environment variables, argv, and process descriptions.
Each format keeps its parsing and escaping rules while sharing policy decisions
and the transaction budget.

For parsed JSON, the input is borrowed and remains unchanged:

```rust
use qubit_redact::Redactor;

let value = serde_json::json!({"password": "raw", "visible": "shown"});
let output = Redactor::standard().redact_json_value(&value);
let inspection = Redactor::standard().inspect_json_value(&value);
assert!(!output.text().as_str().contains("raw"));
assert_eq!(value["password"], "raw");
let _ = inspection;
```

`RedactionBatch::redact_json_value` and the other batch methods share a budget
and publish handles that resolve to final text and summaries.

## 4. Inspection and disabled policies

Inspection reports rule matches, sensitivity, and completion without publishing
raw values. Use it to explain why a field would be masked before choosing a
serialization or logging boundary.

`RedactionPolicy::disabled()` is an explicit opt-out. It preserves the raw
rendered value, so callers must keep it behind a reviewed local boundary.

## 5. Verification

```bash
cargo test --all-features
./align-ci.sh
./ci-check.sh
```

See the [derive guide](https://github.com/qubit-ltd/rs-redact-derive/blob/main/doc/user_guide.md)
for field attributes and generated implementations.

## License

Apache-2.0. See [LICENSE](../LICENSE).
