# qubit-redact User Guide

[README](../README.md) · [中文用户手册](user_guide.zh_CN.md) · [Derive Guide](https://github.com/qubit-ltd/rs-redact-derive/blob/main/doc/user_guide.md)

This guide covers `qubit-redact` 0.5 for application and library authors who
need bounded diagnostic output without changing the source value. A `Redactor`
owns an immutable policy snapshot; each composer or batch owns one budget and
publishes only final text plus its summary.

## Completion is part of the result

Every rendering entry point returns `RedactionTextOutput`: safe text and a
`RedactionSummary`. A complete result may be consumed with
`into_complete_text()`. A truncated or exhausted result returns its summary so
the caller must choose the local presentation policy. For an intentional
fallback marker, use `into_text_or_marker("<redaction incomplete>")` rather
than silently presenting a partial URL, header block, or command description.
When the output must remain borrowed, use `complete_text()` or
`text_or_marker("<redaction incomplete>")`. These borrowed helpers let batch
callers apply the same rule independently to every resolved item.

`Truncated` retains a non-empty safe substitute; `Exhausted` could not retain a
complete replacement under the shared output budget. `reasons()` identifies
parser and budget degradation, including invalid JSON, form, and multipart data.

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
- `keyed_value(name, key, value)` classifies one field value by a sibling
  runtime key, using the same policy semantics as a map entry;
- `json(name, value)` applies recursive JSON handling;
- `skipped(name, access)` omits a field without rendering its value.

Each operation participates in the same output budget and summary. A field
that may contain sensitive data must not be left unmarked merely because the
current policy happens to mask it elsewhere. Unmarked fields are a permanent
downstream-owned trust decision: strict policy and inspection do not infer or
upgrade their sensitivity.

Scalar field APIs accept lazy `Display` values. A `High` or `Secret` decision
happens before formatting, so rejected content is never formatted. A
Debug-only value can be supplied through `format_args!`:

```rust
use std::fmt;

use qubit_redact::Redactor;

struct Request;

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("reviewed-debug-view")
    }
}

let request = Request;
let output = Redactor::strict().redact_field(
    "request",
    &format_args!("{request:?}"),
);
assert!(!output.text().as_str().is_empty());
```

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

JSON text is parsed once into an admitted tree. Invalid JSON and traversal
limit failures fail closed as an opaque or truncated safe result. The borrowed
`Value` path does not clone, stringify, or mutate the caller's value. Within a
domain implementation, `fields.json_value("payload", &value)` writes a parsed
value as JSON rather than as a quoted JSON string. Sequence implementations use
`items.json_value_item(&value)` for the same recursive JSON policy; this matters
for downstream collections whose declared data type is JSON, because each item
must be traversed as JSON instead of formatted as an opaque scalar.

```rust
use qubit_redact::Redact;
use qubit_redact::RedactionWriter;

struct Documents(Vec<serde_json::Value>);

impl Redact for Documents {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.sequence(|items| {
            for value in &self.0 {
                items.json_value_item(value);
            }
        });
    }
}
```

JSON text uses `qubit-json`'s explicit number contract: negative integers must
fit `i64`, non-negative integers must fit `u64`, and fractional/exponential
tokens must produce finite `f64`. Out-of-range text follows the same fail-closed
invalid-JSON path. A former serde_json private Number-marker key is an ordinary
object key.

## 4. Inspection and disabled policies

Inspection reports rule matches, sensitivity, and completion without publishing
raw values. Use it to explain why a field would be masked before choosing a
serialization or logging boundary.

`RedactionPolicy::disabled()` is an explicit confidentiality opt-out. It restores raw values
for fields, JSON, URI, HTTP, environment, argv, process, derive field modes,
and generated Serde output. The source is still bounded by runtime limits and
control characters remain escaped, but neither mechanism makes the result
redacted. Enable this only as reviewed startup configuration and never from an
untrusted request.

```rust
use qubit_redact::{RedactionPolicy, Redactor};

let mut policy = RedactionPolicy::disabled();
assert!(policy.is_disabled());
policy.set_disabled(false);
let output = Redactor::new(policy).redact_field("password", "raw-secret");
assert!(!output.summary().is_redaction_disabled());
assert!(!output.text().as_str().contains("raw-secret"));
```

Enabled `Complete`, `Truncated`, and `Exhausted` text remains confidentiality
safe. Check `summary().completion()` and `summary().reasons()` only when the
caller needs completeness, audit provenance, or retry decisions; do not parse
text markers to infer state. When inspection drives a security decision, treat
an inspection error as sensitive because classification was inconclusive.

## 5. Troubleshooting and limits

- Unexpected raw output: first check `output.summary().is_redaction_disabled()`
  and the policy snapshot used to create the composer or batch.
- Unexpected truncation: inspect `completion()`, `reasons()`, and `usage()`;
  related operations intentionally share limits.
- Missing masking: verify the field name and review every unmarked field. The
  runtime does not infer application-specific sensitivity.
- This crate protects only calls routed through its runtime. It does not erase
  source memory or protect unrelated logging and serialization paths.

## 6. Verification

```bash
cargo test --all-features
./align-ci.sh
./ci-check.sh
```

See the [derive guide](https://github.com/qubit-ltd/rs-redact-derive/blob/main/doc/user_guide.md)
for field attributes and generated implementations.

## License

Apache-2.0. See [LICENSE](../LICENSE).
