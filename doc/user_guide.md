# qubit-redact User Guide

[README](../README.md) · [Chinese guide](user_guide.zh_CN.md) · [derive guide](../derive/README.md)

## Purpose and Audience

For application and library authors using qubit-redact 0.6. Start with business serialization
and diagnostic logging, then configure domain types, input formats, and budgets.

## Installation and Scenario: Login Diagnostics

This dependency configuration supports every example in this section.

```toml
[dependencies]
qubit-redact = { version = "0.6", features = ["derive", "serde", "json"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

```rust
use qubit_redact::{Redact, Redactor};

#[derive(Redact)]
#[redact(crate = qubit_redact)]
#[redact(serde, debug)]
struct Login {
    user: String,
    #[redact(level = "secret")]
    password: String,
}

let login = Login { user: "ada".into(), password: "raw-secret".into() };
let redactor = Redactor::standard();
let view = redactor.redact_view(&login);
assert!(!format!("{view}").contains("raw-secret"));
assert!(!format!("{login:?}").contains("raw-secret"));
let json = redactor.to_json(&login).expect("redacted JSON");
assert_eq!(json, r#"{"user":"ada","password":"<redacted>"}"#);
assert!(!serde_json::to_string(&login).expect("business JSON").contains("raw-secret"));
let output = redactor.redact_text(&login);
assert!(!output.text().as_str().contains("raw-secret"));
```

## Outputs and View Semantics

| Entry point | Result | Execution |
| --- | --- | --- |
| `redact_view(&value)` | `RedactedView<'a, T>` | On each formatting/serialization call |
| `redact_text(&value)` | `RedactionTextOutput` | Immediately, with final text and summary |
| `to_json(&value)` | `Result<String, serde_json::Error>` | Immediately serializes the view |

A view borrows the source and owns a policy snapshot; it is not a modified business object
or cached source content. Each use starts from the source with an independent budget, never
from the previous mask. It supports Display/Debug; structured serialization requires
`RedactSerialize` and never falls back to a Debug string. Interior-mutable sources can change
between uses; the policy remains fixed at view creation.

`redact_text()` produces `output.text()` that can be displayed without another redaction pass.
`to_json()` is equivalent to `serde_json::to_string(&redactor.redact_view(&value))` and propagates
serialization errors. It follows domain annotations; `redact_json(text)` parses input JSON and
classifies JSON keys.

## Domain Types and Field Reference

| Field attribute | Meaning / supported values |
| --- | --- |
| None | Ordinary `Debug`; structured view serialization requires `#[redact(serde)]`. |
| `level = "low"/"medium"/"high"/"secret"` | Final level for each leaf; primitive scalars, `RedactScalar` and recursive supported containers. |
| `level = "...", display` | Explicit textual representation of a `Display` value; no `Debug` or ordinary `Serialize` required. |
| `skip` | Omit while enabled; disabled restores the field. |
| `nested` | Delegate to `Redact`; structured output also requires `RedactSerialize`. |
| `map` | `HashMap`/`BTreeMap` with `String`, `&str`, or `Cow<str>` keys, optionally wrapped in `Option`; values require level capability and `Debug` for pass-through text. |
| `map_key_level = "..."` | Fixed level for each map key; values remain ordinary. |
| `map_key_level = "...", map_value_level = "..."` | Independently fixed key and value levels. |
| `keyed_by = key` | Classify by a sibling `AsRef<str>` key on a named field; value requires level capability and `Debug`. |
| `json` | JSON `String`/`str`/`Cow<str>`, parsed `serde_json::Value`, references and `Option`; requires `json`. |

Container attributes: `debug`, `display`, `serde`, `transparent`, and `crate = path`.
`serde` generates structured redaction for `redact_view()` and makes ordinary `Serialize`
use the redacted representation. It requires the runtime `serde` feature and a direct Serde
dependency.
`transparent` requires exactly one field and delegates its representation; it does not declare scalar capability.
Do not derive ordinary `Debug` together with `debug`, or ordinary `Serialize` together with `serde`.

Built-in level leaves include strings, characters, booleans, integers, floats, and BigDecimal
with `serde`. Level containers include references, Option, Vec, slices, arrays, Box/Rc/Arc,
VecDeque, LinkedList, sets, heaps, standard maps, and tuples up to 12 elements. Ordinary level
mode masks map values and retains keys; use the key-level attributes when needed. Pass-through
text maps and keyed_by require Debug; level-only RedactScalar fields do not.

Serde supports rename/rename_all, enum tag/content/untagged, transparent, skip, skip_serializing,
and skip_serializing_if. with/serialize_with work on ordinary or skipped fields, not on sensitive
modes observing raw field state. flatten is unsupported. JSON text fields retain their string
wire type; parsed Value fields retain JSON structure.

### Scalar Newtypes

```rust
use qubit_redact::{Redact, RedactScalar, Redactor};

#[derive(RedactScalar)]
#[redact(crate = qubit_redact)]
struct Id(u64);

#[derive(RedactScalar)]
#[redact(crate = qubit_redact)]
struct UserId { value: String }

#[derive(Redact)]
#[redact(crate = qubit_redact)]
#[redact(serde)]
struct Account {
    #[redact(level = "secret")]
    id: Id,
    #[redact(level = "secret")]
    user_id: UserId,
}

let account = Account { id: Id(42), user_id: UserId { value: "raw-id".into() } };
assert_eq!(Redactor::standard().to_json(&account).expect("account JSON"),
    r#"{"id":"<redacted>","user_id":"<redacted>"}"#);
```

### Third-Party Display Types

Select textual representation explicitly. High/Secret do not invoke Display; Low/Medium and
disabled policies format only when needed, under the resource budget. Disabled mode retains
the explicitly selected string representation.

```rust
use qubit_redact::{Redact, Redactor};

struct ExternalId(u64);
impl std::fmt::Display for ExternalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(value) = self;
        write!(f, "external-{value}")
    }
}

#[derive(Redact)]
#[redact(crate = qubit_redact)]
#[redact(serde)]
struct Event {
    #[redact(level = "secret", display)]
    id: ExternalId,
}
let event = Event { id: ExternalId(42) };
assert_eq!(Redactor::standard().to_json(&event).expect("event JSON"),
    r#"{"id":"<redacted>"}"#);
```

### Levels and Policy Precedence

| Decision source | Can runtime policy raise the level? |
| --- | --- |
| Derived level, Display level, map key/value level | No: the explicit level is final |
| Manual fields.sensitive(level, ...) | Yes: the argument is a minimum |
| map, keyed_by, redact_field | Classified by runtime rules |
| Unmarked fields and unmarked | No classification; ordinary output |

Default Low retains two leading and two trailing characters, fully hiding short strings;
Medium retains one trailing character; High emits `****`; Secret emits `<redacted>`.
For example, `abcdef` becomes `ab****ef` at Low and `*******f` at Medium.
Business types choose the correct level; strict policy does not override explicit declarations.

### Sharing a Budget Across Values

HTTP URL/headers/body or process argv/env often belong to one diagnostic event. Batch operations
share one budget; separate one-shot calls and repeated view uses each get their own budget.
Items consume allowance in insertion order, so earlier items can exhaust resources needed by
later ones. `finish_for_diagnostics(marker)` returns one escaped marker for incomplete items
and invalid/foreign handles. `summary()` is aggregate accounting, not per-item auditing.

```rust
use qubit_redact::Redactor;
let mut batch = Redactor::standard().batch();
let user = batch.redact_field("user", "ada");
let password = batch.redact_field("password", "raw-secret");
let output = batch.finish_for_diagnostics("<incomplete>");
assert_eq!(output.text(user).as_str(), "ada");
assert_eq!(output.text(password).as_str(), "<redacted>");
```

## Input Formats and Integrations

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
| `derive` | `#[derive(Redact)]
#[redact(crate = qubit_redact)]` |
| `serde` | generated/domain structured Serde adapters and BigDecimal support |
| `json` | JSON text and borrowed `serde_json::Value` handling |
| `http` | JSON plus URL, headers, form, multipart, and body capture |
| `uri` | generic URI parsing and redaction |

Keep the default empty feature set for scalar and manually implemented domain
redaction. In the 0.6 release line, `serde` continues to include
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
[derive README](../derive/README.md).

To validate a local checkout:

```bash
cargo test --all-features
./align-ci.sh
./ci-check.sh
```


## License

Apache-2.0. See [LICENSE](../LICENSE).
