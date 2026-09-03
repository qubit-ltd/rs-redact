# qubit-redact User Guide

[README](../README.md) · [中文用户手册](user_guide.zh_CN.md) · [Design](design.md) · [Derive Guide](https://github.com/qubit-ltd/rs-redact-derive/blob/main/doc/user_guide.md)

## Purpose and Audience

This guide covers `qubit-redact` 0.5 for application and library authors who
need bounded diagnostic output without changing the source value. Use it when
values may reach logs, errors, or support tooling and the application must
decide which fields are sensitive. It does not protect output that bypasses the
runtime or erase source memory.

## Conceptual Model

`Redactor` owns an immutable policy snapshot. A composer or batch starts one
bounded rendering transaction and publishes owned text plus a summary:

```text
borrowed value -> policy decision + transaction budget
                  -> composer: RedactionTextOutput
                  -> batch: handles + fail-closed diagnostics
                  -> inspection: Result<RedactionInspection, Error>
```

Single-value conveniences and composers return `RedactionTextOutput`. Batches
publish independently addressable diagnostic text through opaque handles;
inspection returns a non-rendering `Result`. Every rendered operation carries
safe text and a `RedactionSummary`. With redaction enabled, text published as `Complete`,
`Truncated`, or `Exhausted` remains confidentiality-safe. The latter two states
mean that diagnostic information is incomplete, not that the text leaked its
source. `Debug`, `Display`, and ordinary diagnostic logging can therefore use
`output.text()` directly; forcing those callers to branch on a reason would not
give them a meaningful recovery action.

Inspect `completion()` and `reasons()` when completeness itself affects audit,
retry, program logic, or a structured output contract. Such callers can use
`complete_text()` / `into_complete_text()` to reject incomplete results, or
`text_or_marker()` / `into_text_or_marker()` to select a presentation fallback.
`Truncated` retains a safe admitted representation; `Exhausted` means the
shared budget could not retain a complete replacement. Reasons identify parser
and budget degradation, including invalid JSON, form, and multipart data.

## Scenario: publish login diagnostics without a password

An authentication service wants to include a user name and a password-bearing
request field in one diagnostic event. The user name must remain visible, the
password must not appear in output, and a budget failure must use one known
fallback. A batch gives every related value the same policy and budget:

```rust
use qubit_redact::Redactor;

let mut batch = Redactor::standard().batch();
let user = batch.redact_field("user", "ada");
let password = batch.redact_field("password", "raw-password");
let output = batch.finish_for_diagnostics("<redaction incomplete>");

assert_eq!(output.text(user).as_str(), "ada");
assert!(!output.text(password).as_str().contains("raw-password"));
```

`finish_for_diagnostics()` maps an incomplete item, an invalid item, and a
handle from another batch to the same escaped marker without returning
`Result`. This deliberately keeps diagnostic presentation fail-closed instead
of exposing a parallel fallible publication model.

## Installation and Minimal Configuration

Add the crate, then opt into only the integrations used by the application:

```toml
[dependencies]
qubit-redact = { version = "0.5" }
```

The default feature set is empty. Enable `derive` for `#[derive(Redact)]` and
also enable `serde` when derived fields use generated serialization adapters.
Enable `serde` directly for redacted serialization, and the `json`, `http`, or `uri` feature
only when the corresponding input format is needed.

## Core Workflow

### Render a domain value

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

### Choose field scopes

`RedactionWriter` exposes explicit field decisions:

- `unmarked(name, access)` renders a reviewed ordinary value;
- `sensitive(level, name, access)` applies a sensitivity mask;
- `nested(name, value)` delegates to another `Redact` implementation;
- `map(name, value)` applies key-aware handling to supported maps;
- `keyed_value(name, key, value)` classifies one field value by a sibling
  runtime key, using the same policy semantics as a map entry;
- `json(name, value)` applies recursive JSON handling;
- `skipped(name, access)` omits a field without rendering its value.

Each operation participates in the same output budget and summary. Unmarked
fields are intentionally passed through because sensitivity is a property of
the downstream business domain, not something a generic framework can infer
from a Rust type, field name, or current contents. Ordinary fields are the vast
majority, so requiring an explicit "not sensitive" annotation on all of them
would add noise without adding knowledge. Downstream code must explicitly mark
fields that can contain sensitive data and repeat that review when its domain
model changes. Strict policy and inspection deliberately do not override that
domain decision.

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

### Render other formats

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

### Redact one HTTP exchange in a batch

Keep the URL, headers, and captured body in one transaction when they belong
to the same diagnostic event:

```rust
use http::{HeaderMap, HeaderValue};
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

let mut headers = HeaderMap::new();
headers.insert("authorization", HeaderValue::from_static("Bearer raw-token"));
let content_type = HeaderValue::from_static("application/json");
let body = br#"{"user":"ada","password":"raw-password"}"#;

let mut batch = Redactor::standard().batch();
let url = batch.redact_http_url("https://example.test/login?token=raw-token");
let headers_handle = batch.redact_http_headers(&headers);
let body_handle = batch.redact_http_body(BodyCapture::complete(body), Some(&content_type));
let output = batch.finish_for_diagnostics("<redaction incomplete>");

for handle in [url, headers_handle, body_handle] {
    assert!(!output.text(handle).as_str().contains("raw-"));
}
```

`BodyCapture::complete` asserts that all source bytes are present.
`BodyCapture::prefix` records a known total length, while
`BodyCapture::truncated_unknown` records that bytes are missing but their count
is unknown. Source truncation is distinct from output truncation and is exposed
as `RedactionReason::SourceTruncated`; never construct a complete capture from
an incomplete body.

### Inspect a URI before accepting it

Inspection is useful when a URI must be rejected rather than merely redacted.
Both a sensitive result and an error are fail-closed outcomes:

```rust
use qubit_redact::Redactor;

let candidate = "https://example.test/?token=raw-token";
let acceptable = Redactor::strict()
    .inspect_uri(candidate)
    .is_ok_and(|inspection| !inspection.contains_sensitive());
assert!(!acceptable);
```

### Redact argv, environment, and process diagnostics

Explicitly classified argv is preferable when the caller knows the argument
contract. Heuristic argv recognizes supported option forms but is not a shell
parser:

```rust
use std::ffi::OsStr;

use qubit_redact::{Redactor, Sensitivity};
use qubit_redact::formats::argv::ArgvItem;

let arguments = [
    ArgvItem::plain(OsStr::new("--server=example.test")),
    ArgvItem::sensitive(OsStr::new("raw-token"), Sensitivity::Secret),
];
let variables = [(OsStr::new("PASSWORD"), OsStr::new("raw-password"))];
let output = Redactor::standard().redact_process(OsStr::new("client"), arguments, variables);
assert!(!output.text().as_str().contains("raw-"));
```

### Feature selection

| Feature | Adds |
| --- | --- |
| `derive` | `#[derive(Redact)]` |
| `serde` | generated/domain structured Serde adapters and BigDecimal support |
| `json` | JSON text and borrowed `serde_json::Value` handling |
| `http` | JSON plus URL, headers, form, multipart, and body capture |
| `uri` | generic URI parsing and redaction |

Keep the default empty feature set for scalar and manually implemented domain
redaction. In the 0.5 compatibility line, `serde` continues to include
BigDecimal support; separating that dependency would require an explicit
feature migration in a later breaking release.

## Advanced Usage

### Inspect decisions and control policies

Inspection reports rule matches, sensitivity, and completion without publishing
raw values. Use it to explain why a field would be masked before choosing a
serialization or logging boundary.

Build one immutable policy and share the resulting `Redactor`. Builder closures
are transactional: an invalid field rule leaves the prior builder unchanged.

```rust
use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};

let policy = RedactionPolicy::builder()
    .fields(|fields| {
        fields.raise("session_id", Sensitivity::High);
    })
    .expect("valid field rule")
    .limits(|limits| {
        limits.max_input_bytes(64 * 1024);
        limits.max_output_bytes(8 * 1024);
        limits.max_collection_items(256);
    })
    .expect("valid limits")
    .build()
    .expect("valid policy");
let redactor = Redactor::new(policy);
assert!(!redactor.redact_field("session_id", "raw-session").text().as_str().contains("raw-session"));
```

`RedactionPolicy::disabled()` is an explicit confidentiality opt-out and an
intentional process-wide debugging escape hatch. It restores raw values for
fields, JSON, URI, HTTP, environment, argv, process, derive field modes, and
generated Serde output. The source is still bounded by runtime limits and
control characters remain escaped, but neither mechanism makes the result
redacted. The framework executes the selected policy; downstream code owns the
authorization, environment, timing, and consequences of disabling it. A
request-controlled switch is usually unsafe, but preventing deliberate or
accidental API misuse is not a framework guarantee.

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

`Redactor::replace_application_default()` affects future calls to
`application_default()` and generated formatting that obtains a new snapshot.
Existing redactors, composers, and batches keep the immutable snapshot they
already own; replacement does not retroactively toggle in-flight work.

## Errors and Diagnostics

Use `summary().completion()`, `summary().reasons()`, and `summary().usage()`
when the caller needs to distinguish a complete result from a budget or parser
degradation. Do not infer that state by parsing displayed text. For strict
presentation, `complete_text()` and `into_complete_text()` reject an incomplete
result; for diagnostic presentation, `text_or_marker()` and
`into_text_or_marker()` select an explicit fallback. An inspection error means
classification was inconclusive and should be treated as sensitive when the
result controls a security decision.

## Troubleshooting

- Unexpected raw output: first check `output.summary().is_redaction_disabled()`
  and the policy snapshot used to create the composer or batch.
- Unexpected truncation: inspect `completion()`, `reasons()`, and `usage()`;
  related operations intentionally share limits.
- Missing masking: verify the field name and review every unmarked field. The
  runtime does not infer application-specific sensitivity.

## Limitations and Best Practices

- Mark fields as sensitive from domain knowledge; `unmarked` and unannotated
  derive fields intentionally remain visible.
- Do not expose `RedactionPolicy::disabled()` to request-controlled inputs; it
  restores raw values and is intended only as a process-wide debugging escape
  hatch.
- This crate protects only calls routed through its runtime. It does not erase
  source memory or protect unrelated logging and serialization paths.

## Further Reading

Read the [README](../README.md), [中文用户手册](user_guide.zh_CN.md),
[API documentation](https://docs.rs/qubit-redact), and the
[derive guide](https://github.com/qubit-ltd/rs-redact-derive/blob/main/doc/user_guide.md).

To validate a local checkout:

```bash
cargo test --all-features
./align-ci.sh
./ci-check.sh
```


## License

Apache-2.0. See [LICENSE](../LICENSE).
