# qubit-redact User Guide

[README](../README.md) · [Chinese guide](user_guide.zh_CN.md) · [derive guide](../derive/README.md) · [API reference](https://docs.rs/qubit-redact/0.8.0/qubit_redact/)

This guide covers **qubit-redact 0.8.0** and requires **Rust 1.94+**. It is for
application and library authors: start with business serialization and diagnostic logging,
then configure domain types, input formats, and budgets. Every Rust block is a complete
program you can place in `src/main.rs` of a test app.

## Contents

- [Conceptual Model](#conceptual-model)
- [Installation](#installation)
- [Quick Start: Redact One Field](#quick-start-redact-one-field)
- [Scenario: Login Diagnostics](#scenario-login-diagnostics)
- [Outputs and View Semantics](#outputs-and-view-semantics)
- [Choose an Entry Point](#choose-an-entry-point)
- [Compose One Diagnostic Message](#compose-one-diagnostic-message)
- [Composer vs Batch](#composer-vs-batch)
- [Domain Types and Field Reference](#domain-types-and-field-reference)
- [Input Formats and Integrations](#input-formats-and-integrations)
- [Advanced Usage](#advanced-usage)
- [Standard vs Strict Policy](#standard-vs-strict-policy)
- [Field Rules, Floors, and Allow Lists](#field-rules-floors-and-allow-lists)
- [Budget Units and Migration to 0.8](#budget-units-and-migration-to-08)
- [Errors and Diagnostics](#errors-and-diagnostics)
- [Handle Incomplete Results](#handle-incomplete-results)
- [Troubleshooting](#troubleshooting)
- [Concurrency and Runtime Constraints](#concurrency-and-runtime-constraints)
- [Limitations and Best Practices](#limitations-and-best-practices)
- [Further Reading](#further-reading)

## Purpose and Audience

For application and library authors using qubit-redact 0.8. Start with business serialization
and diagnostic logging, then configure domain types, input formats, and budgets.

## Conceptual Model

qubit-redact separates the source value, the policy snapshot, and the rendered
result. A `RedactedView` borrows the source and applies its snapshot whenever
it is formatted or serialized; `redact_text()` and `to_json()` execute the
operation immediately. A batch groups several inputs under one transaction
budget. None of these results modifies the source value.

## Installation

This dependency configuration supports every example in this section.

<!-- redact-example: kind=cargo features=derive,serde,json -->
```toml
[dependencies]
qubit-redact = { version = "0.8", features = ["derive", "serde", "json"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

## Quick Start: Redact One Field

Before configuring domain types, confirm the scalar path. The built-in standard policy already
classifies common names such as `password` as secret, so no optional features or custom rules are
required. Save the program below as `src/main.rs` and run `cargo run`.

<!-- redact-example: kind=cargo features=none -->
```toml
[dependencies]
qubit-redact = "0.8"
```

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::Redactor;

fn main() {
    let output = Redactor::standard().redact_field("password", "raw-secret");
    assert_eq!(output.text().as_str(), "<redacted>");
    assert_eq!(output.summary().completion(), qubit_redact::RedactionCompletion::Complete);
}
```

The source string in memory stays unchanged; only the rendered diagnostic text is redacted.
Use this path for one-off log fields, error context keys, or quick experiments before investing
in derive annotations.

## Scenario: Login Diagnostics

The following login object keeps its source password unchanged while both diagnostic
formatting and direct business serialization must hide it. The explicit
`#[redact(serde)]` annotation selects that serialization boundary. Later examples
show how to keep ordinary business serialization separate when it needs the raw value.

<!-- redact-example: kind=run features=derive,serde,json -->
```rust
use qubit_redact::{Redact, Redactor};

#[derive(Redact)]
#[redact(serde, debug)]
struct Login {
    user: String,
    #[redact(level = "secret")]
    password: String,
}

fn main() {
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
}
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
the derive-generated `RedactSerialize` capability; callers need not
implement hidden traits. It never falls back to a Debug string. Interior-mutable sources can change
between uses; the policy remains fixed at view creation.

`redact_text()` produces `output.text()` that can be displayed without another redaction pass.
`to_json()` shares the view's projection and policy and additionally bounds final JSON bytes.
With identical source state, outputs match when both succeed. It traverses once, propagates
serializer and budget errors, and never returns partial JSON. Success may include safe structural
replacements and is not a completeness assertion. It follows domain annotations;
`redact_json(text)` parses input JSON and classifies JSON keys.

## Choose an Entry Point

| Need | Entry point | Typical use |
| --- | --- | --- |
| Redact one named scalar | `redact_field(field, value)` | Log lines, error keys, quick diagnostics |
| Lazy formatting under a fixed policy | `redact_view(&value)` | Pass into `format!`, tracing fields, or custom serializers |
| Final text and summary now | `redact_text(&value)` | Build one string before writing to logs or HTTP bodies |
| Compact redacted JSON | `to_json(&value)` | Structured diagnostics without an external serializer |
| Borrowed JSON input | `redact_json(text)` / `redact_json_value(&value)` | Payloads that are already JSON |
| Several values, one budget | `diagnostic_batch()` | HTTP exchange parts, argv/env tuples, multi-field events |
| One ordered message | `text_composer()` | Prefix + field + domain value in a single line |
| Classify without rendering | `inspect_*` | Gateways, validators, pre-flight checks |

Pick the narrowest entry point. Views defer work until formatting; composers and batches share one
transaction budget but publish different result shapes. Inspection never formats field contents and
reports `usage().output_bytes() == 0` on success.

## Compose One Diagnostic Message

`text_composer()` builds one ordered diagnostic string under a single budget. Chain literals,
policy-classified fields, domain values, argv fragments, and environment assignments; call
`finish()` once to obtain `RedactionTextOutput`.

<!-- redact-example: kind=run features=none -->
```rust
use std::ffi::OsStr;

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::formats::argv::ArgvItem;

fn main() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.secret_sensitive("password");
        })
        .expect("valid field rule")
        .build()
        .expect("valid policy");
    let redactor = Redactor::new(policy);
    let output = redactor
        .text_composer()
        .literal("request password=")
        .field("password", "super-secret")
        .literal(" argv=")
        .argv(|argv| {
            argv.items([ArgvItem::plain(OsStr::new("client"))]);
        })
        .finish();
    assert_eq!(output.text().as_str(), "request password=<redacted> argv=[\"client\"]");
    assert!(!output.text().as_str().contains("super-secret"));
}
```

Each `finish()` starts from a fresh budget. Reusing the same `Redactor` is fine; reusing an old
output buffer is not—the library never mutates a finalized `RedactionTextOutput`.

## Composer vs Batch

Both share one policy snapshot and one transaction budget, but they answer different questions.

| Model | Publishes | Best for |
| --- | --- | --- |
| `text_composer()` | One concatenated `RedactionTextOutput` | Single log line or error message |
| `diagnostic_batch()` | Per-item handles resolved through `finish_with_marker` | Inspecting parts independently, HTTP URL vs headers vs body |

Batch handles are valid only for the batch that created them. Resolving a handle from an earlier
batch through a later `finish_with_marker` returns the escaped fallback marker, not the original
text. Composers do not expose handles; the entire message succeeds or degrades as one unit.

Environment variables follow the same split: compose inline assignments with `.env(...)`, or add
`redact_env(name, value)` items to a batch when each name may need separate inspection later.

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::Redactor;
use std::ffi::OsStr;

fn main() {
    let redactor = Redactor::standard();
    let composed = redactor
        .text_composer()
        .env(|env| {
            env.pair("MODE", "debug");
            env.os_pairs([(OsStr::new("REGION"), OsStr::new("ap-east-1"))]);
        })
        .finish();
    let mut batch = redactor.diagnostic_batch();
    let password = batch.redact_env("PASSWORD", "raw-secret");
    let output = batch.finish_with_marker("<incomplete>");
    assert_eq!(composed.text().as_str(), r#"MODE=debug["REGION=ap-east-1"]"#);
    assert_eq!(output.text(password).as_str(), "PASSWORD=<redacted>");
}
```

## Domain Types and Field Reference

| Field attribute | Meaning / supported values |
| --- | --- |
| None | Ordinary `Debug`; with the runtime `serde` feature, the view serializes through its generated redacted projection when fields support Serde. |
| `level = "low"/"medium"/"high"/"secret"` | Final level for each leaf; primitive scalars, `RedactScalar` and recursive supported containers. |
| `level = "...", display` | Explicit textual representation of a `Display` value; no `Debug` or ordinary `Serialize` required. |
| `skip` | Omit while enabled; disabled restores the field. |
| `nested` | Delegate to `Redact`; structured output follows the nested value's generated view projection. |
| `map` | `HashMap`/`BTreeMap` with `String`, `&str`, or `Cow<str>` keys, optionally wrapped in `Option`; values require level capability and `Debug` for pass-through text. |
| `map_key_level = "..."` | Fixed level for each map key; values remain ordinary. |
| `map_key_level = "...", map_value_level = "..."` | Independently fixed key and value levels. |
| `keyed_by = key` | Classify by a sibling `AsRef<str>` key on a named field; value requires level capability and `Debug`. |
| `json` | JSON `String`/`str`/`Cow<str>`, parsed `serde_json::Value`, references and `Option`; requires `json`. |

Container attributes: `debug`, `display`, `serde`, `transparent`, and `crate = path`.
The runtime `serde` feature generates structured redaction for `redact_view()` for every
derived type. `#[redact(serde)]` additionally makes the source type's ordinary `Serialize`
use that redacted representation. Without it, a separately derived ordinary `Serialize`
remains unchanged. Enable the runtime `serde` feature; generated implementations do not
require a direct Serde dependency. Add `serde` when your own code uses its traits or derives.
`transparent` requires exactly one field and delegates its representation; it does not declare scalar capability.
Do not derive ordinary `Debug` together with `debug`, or ordinary `Serialize` together with `serde`.

### Choosing the serialization boundary

With the runtime `serde` feature, `Redact` always generates the redacted projection used by
`redact_view()` and `to_json()`. The source type does not need to implement `Serialize` for
that projection to be usable. Its fields must only satisfy the requirements of their redaction
mode: an unmarked field normally needs `Serialize`, while `level = "...", display` needs
`Display` and emits a redacted string.

<!-- redact-example: kind=run features=derive,serde,json -->
```rust
use qubit_redact::{Redact, Redactor};

#[derive(Redact, serde::Serialize)]
struct Login {
    user: String,
    #[redact(level = "secret")]
    password: String,
}

fn main() {
    let login = Login { user: "ada".into(), password: "raw-secret".into() };
    assert!(serde_json::to_string(&login).expect("business JSON").contains("raw-secret"));
    assert!(!Redactor::standard().to_json(&login).expect("redacted JSON").contains("raw-secret"));
}
```

Add `#[redact(serde)]` when direct source serialization must also be redacted. If the type has
neither ordinary `Serialize` nor `#[redact(serde)]`, direct serialization is unavailable, but
the view and `to_json()` still work when the generated projection can serialize its fields.
If a required field capability is missing, formatting the view still works; attempting structural
serialization of the view or calling `to_json()` produces a compile-time trait-bound error.

Built-in level leaves include strings, characters, booleans, integers, floats, and BigDecimal
with `bigdecimal`. Level containers include references, Option, Vec, slices, arrays, Box/Rc/Arc,
VecDeque, LinkedList, sets, heaps, standard maps, and tuples up to 12 elements. Ordinary level
mode masks map values and retains keys; use the key-level attributes when needed. Pass-through
text maps and keyed_by require Debug; level-only RedactScalar fields do not.

### Hand-written keyed nested values

Use `fields.keyed_nested(display_name, business_key, value)` when a hand-written
`Redact` implementation wraps another `Redact + Debug` value and the business key chooses
the payload policy. If the business key is public, the method delegates to the child so its
own field rules, JSON traversal, and inspection still run. If the business key is sensitive,
the payload is masked as one value; disabled policy renders the original value. This prevents
a public wrapper from exposing a nested secret through a `Debug` fallback.

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::{Redact, RedactionWriter, Sensitivity};

struct NamedPayload { name: String, payload: Payload }
#[derive(Debug)]
struct Payload { password: String }

impl Redact for Payload {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Payload", |fields| {
            fields.sensitive_at_least(Sensitivity::Secret, "password", || &self.password);
        });
    }
}

impl Redact for NamedPayload {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("NamedPayload", |fields| {
            fields.unredacted("name", || &self.name);
            fields.keyed_nested("payload", &self.name, &self.payload);
        });
    }
}

fn main() {
    let payload = NamedPayload {
        name: "public".into(),
        payload: Payload { password: "raw-secret".into() },
    };
    let output = qubit_redact::Redactor::standard().redact_text(&payload);
    assert!(!output.text().as_str().contains("raw-secret"));
}
```

Serde supports rename/rename_all, enum tag/content/untagged, transparent, skip, skip_serializing,
and skip_serializing_if. with/serialize_with work on ordinary or skipped fields, not on sensitive
modes observing raw field state. flatten is unsupported. JSON text fields retain their string
wire type; parsed Value fields retain JSON structure.

### Scalar Newtypes

<!-- redact-example: kind=run features=derive,serde,json -->
```rust
use qubit_redact::{Redact, RedactScalar, Redactor};

#[derive(RedactScalar)]
struct Id(u64);

#[derive(RedactScalar)]
struct UserId { value: String }

#[derive(Redact)]
#[redact(serde)]
struct Account {
    #[redact(level = "secret")]
    id: Id,
    #[redact(level = "secret")]
    user_id: UserId,
}

fn main() {
    let account = Account { id: Id(42), user_id: UserId { value: "raw-id".into() } };
    assert_eq!(Redactor::standard().to_json(&account).expect("account JSON"),
        r#"{"id":"<redacted>","user_id":"<redacted>"}"#);
}
```

### Third-Party Display Types

Select textual representation explicitly. High/Secret do not invoke Display; Low/Medium and
disabled policies format only when needed, under the resource budget. Disabled mode retains
the explicitly selected string representation.

<!-- redact-example: kind=run features=derive,serde,json -->
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
#[redact(serde)]
struct Event {
    #[redact(level = "secret", display)]
    id: ExternalId,
}

fn main() {
    let event = Event { id: ExternalId(42) };
    assert_eq!(Redactor::standard().to_json(&event).expect("event JSON"),
        r#"{"id":"<redacted>"}"#);
}
```

### Levels and Policy Precedence

| Decision source | Can runtime policy raise the level? |
| --- | --- |
| Derived level, Display level, map key/value level | No: the explicit level is final |
| Manual fields.sensitive_at_least(level, ...) | Yes: the argument is a minimum |
| map, keyed_by, redact_field | Classified by runtime rules |
| Unmarked fields and `unmarked` | No classification; ordinary output |

Default Low retains two leading and two trailing characters, fully hiding short strings;
Medium retains one trailing character; High emits `****`; Secret emits `<redacted>`.
For example, `abcdef` becomes `ab****ef` at Low and `*******f` at Medium.
Business types choose the correct level; strict policy does not override explicit declarations.

| Level | Example value | Masked output |
| --- | --- | --- |
| Low | `abcdef` | `ab****ef` |
| Low | `ab` | `<redacted>` (short strings fully hidden) |
| Medium | `abcdef` | `*******f` |
| High | any | `****` |
| Secret | any | `<redacted>` |

### Sharing a Budget Across Values

HTTP URL/headers/body or process argv/env often belong to one diagnostic event. Batch operations
share one budget; separate one-shot calls and repeated view uses each get their own budget.
Items consume allowance in insertion order, so earlier items can exhaust resources needed by
later ones. `finish_with_marker(marker)` returns one escaped marker for incomplete items
and invalid/foreign handles. `finish()` uses `<redaction incomplete>`. `summary()` is aggregate accounting, not per-item auditing.

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::Redactor;

fn main() {
    let mut batch = Redactor::standard().diagnostic_batch();
    let user = batch.redact_field("user", "ada");
    let password = batch.redact_field("password", "raw-secret");
    let output = batch.finish_with_marker("<incomplete>");
    assert_eq!(output.text(user).as_str(), "ada");
    assert_eq!(output.text(password).as_str(), "<redacted>");
}
```

## Input Formats and Integrations

### Render other formats

The runtime provides bounded redaction for JSON text and values, URI, HTTP
headers/query data, environment variables, argv, and process descriptions.
Each format keeps its parsing and escaping rules while sharing policy decisions
and the transaction budget.

For parsed JSON, the input is borrowed and remains unchanged:

<!-- redact-example: kind=run features=json -->
```rust
use qubit_redact::Redactor;

fn main() {
    let value = serde_json::json!({"password": "raw", "visible": "shown"});
    let output = Redactor::standard().redact_json_value(&value);
    let inspection = Redactor::standard().inspect_json_value(&value);
    assert!(!output.text().as_str().contains("raw"));
    assert_eq!(value["password"], "raw");
    let _ = inspection;
}
```

`DiagnosticRedactionBatch::redact_json_value` and the other batch methods share a budget.
After `finish_with_marker`, handles select complete item text or the escaped
fallback marker; `summary()` describes the entire batch.

JSON text is parsed once into an admitted tree. Invalid JSON and traversal
limit failures fail closed as an opaque or truncated safe result. The borrowed
`Value` path does not clone, stringify, or mutate the caller's value. Within a
domain implementation, `fields.json_value("payload", &value)` writes a parsed
value as JSON rather than as a quoted JSON string. Sequence implementations use
`items.json_value_item(&value)` for the same recursive JSON policy; this matters
for downstream collections whose declared data type is JSON, because each item
must be traversed as JSON instead of formatted as an opaque scalar.

<!-- redact-example: kind=run features=json -->
```rust
use qubit_redact::Redact;
use qubit_redact::RedactionWriter;

struct Documents(Vec<serde_json::Value>);

impl Redact for Documents {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        let Self(documents) = self;
        writer.sequence(|items| {
            items.for_each(documents, |items, value| {
                items.json_value_item(value);
            });
        });
    }
}

fn main() {
    let documents = Documents(vec![serde_json::json!({"password": "raw"})]);
    let output = qubit_redact::Redactor::standard().redact_text(&documents);
    assert!(!output.text().as_str().contains("raw"));
}
```

JSON text uses `qubit-json`'s explicit number contract: negative integers must
fit `i64`, non-negative integers must fit `u64`, and fractional/exponential
tokens must produce finite `f64`. Out-of-range text follows the same fail-closed
invalid-JSON path. A former serde_json private Number-marker key is an ordinary
object key.

### Redact one HTTP exchange in a batch

Enable the runtime `http` feature and add `http = "1"` to your dependencies for this example.

Keep the URL, headers, and captured body in one transaction when they belong
to the same diagnostic event:

<!-- redact-example: kind=run features=http -->
```rust
use http::{HeaderMap, HeaderValue};
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

fn main() {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", HeaderValue::from_static("Bearer raw-token"));
    let content_type = HeaderValue::from_static("application/json");
    let body = br#"{"user":"ada","password":"raw-password"}"#;

    let mut batch = Redactor::standard().diagnostic_batch();
    let url = batch.redact_http_url("https://example.test/login?token=raw-token");
    let headers_handle = batch.redact_http_headers(&headers);
    let body_handle = batch.redact_http_body(BodyCapture::complete(body), Some(&content_type));
    let output = batch.finish_with_marker("<redaction incomplete>");

    for handle in [url, headers_handle, body_handle] {
        assert!(!output.text(handle).as_str().contains("raw-"));
    }
}
```

`BodyCapture::complete` asserts that all source bytes are present.
`BodyCapture::prefix` records a known total length, while
`BodyCapture::truncated_unknown` records that bytes are missing but their count
is unknown. Source truncation is distinct from output truncation and is exposed
as `RedactionReason::SourceTruncated`; never construct a complete capture from
an incomplete body.

### Inspect a URI before accepting it

Enable the runtime `uri` feature for this example.

Inspection is useful when a URI must be rejected rather than merely redacted.
Both a sensitive result and an error are fail-closed outcomes:

<!-- redact-example: kind=run features=uri -->
```rust
use qubit_redact::Redactor;

fn main() {
    let candidate = "https://example.test/?token=raw-token";
    let acceptable = Redactor::strict()
        .inspect_uri(candidate)
        .is_ok_and(|inspection| !inspection.contains_sensitive());
    assert!(!acceptable);
}
```

### Redact argv, environment, and process diagnostics

Explicitly classified argv is preferable when the caller knows the argument
contract. Heuristic argv recognizes supported option forms but is not a shell
parser:

<!-- redact-example: kind=run features=none -->
```rust
use std::ffi::OsStr;

use qubit_redact::{Redactor, Sensitivity};
use qubit_redact::formats::argv::ArgvItem;

fn main() {
    let arguments = [
        ArgvItem::plain(OsStr::new("--server=example.test")),
        ArgvItem::sensitive(OsStr::new("raw-token"), Sensitivity::Secret),
    ];
    let variables = [(OsStr::new("PASSWORD"), OsStr::new("raw-password"))];
    let output = Redactor::standard().redact_process(OsStr::new("client"), arguments, variables);
    assert!(!output.text().as_str().contains("raw-"));
}
```

### Feature selection

| Feature | Adds |
| --- | --- |
| `derive` | `#[derive(Redact)]`, `#[derive(RedactScalar)]` |
| `serde` | generated/domain structured Serde adapters |
| `bigdecimal` | BigDecimal scalar and level support; includes `serde` |
| `json` | JSON text and borrowed `serde_json::Value` handling |
| `http` | JSON plus URL, headers, form, multipart, and body capture |
| `uri` | generic URI parsing and redaction |

Keep the default empty feature set for scalar and manually implemented domain
redaction. In the 0.8 release line, `serde` provides structured serialization,
while BigDecimal support is enabled explicitly with the `bigdecimal` feature.

## Standard vs Strict Policy

`Redactor::standard()` uses the built-in field catalog and leaves unrecognized scalar names visible.
Use it when domain types already declare sensitivity or when unknown keys are intentionally diagnostic.

`Redactor::strict()` treats unrecognized scalar fields as secret. Use it for untrusted key/value maps,
user-supplied query parameters, or third-party JSON where field names are not under your control.

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::Redactor;

fn main() {
    let field = "custom_metric";
    let value = "visible-value";
    assert!(
        !Redactor::standard()
            .redact_field(field, value)
            .text()
            .as_str()
            .contains("<redacted>")
    );
    assert_eq!(
        Redactor::strict().redact_field(field, value).text().as_str(),
        "<redacted>"
    );
}
```

Strict mode does not override explicit derive levels or hand-written `sensitive_at_least` floors on
domain types; it applies to runtime field classification paths such as `redact_field`, JSON keys,
and HTTP query parameters.

## Advanced Usage

### Inspect decisions and control policies

Inspection reports rule matches, sensitivity, and completion without publishing
raw values. Use it to explain why a field would be masked before choosing a
serialization or logging boundary.

Inspection never invokes `Debug`, `Display`, or `Serialize` on classified values. A formatter that
panics during rendering would still allow inspection to complete, which makes inspection suitable
for security gates that must not leak data even when logging is misconfigured.

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;

fn main() {
    let inspection = Redactor::standard()
        .inspect_field("password", "raw-secret")
        .expect("field inspection should complete");
    assert!(inspection.contains_sensitive());
    assert_eq!(inspection.max_sensitivity(), Some(Sensitivity::Secret));
    assert_eq!(inspection.usage().output_bytes(), 0);
}
```

Parallel `inspect_*` entry points exist for domain values, JSON text and values, HTTP parts, URI,
argv, environment pairs, and full process descriptions. Treat any inspection error as inconclusive
when the result controls admission.

Build one immutable policy and share the resulting `Redactor`. Builder closures
are transactional: an invalid field rule leaves the prior builder unchanged.

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};

fn main() {
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
}
```

### Field Rules, Floors, and Allow Lists

Runtime field rules complement derive annotations; they never lower an explicit derive level.
Common builder actions include:

| Builder call | Effect |
| --- | --- |
| `secret_sensitive(name)` | Classify an exact field name as secret |
| `raise(name, level)` | Raise runtime classification to at least the given level |
| `allow_exact` / `allow_suffix` | Permit listed names to stay unclassified |
| `floor(floor)` | Install a minimum redaction floor for matching names |

A floor can raise sensitivity above an allow rule when both match the same name. Floors are useful
for provider-specific tokens that must never appear verbatim even if an allow list would otherwise
permit the field.

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::{RedactionFloor, RedactionPolicy, Redactor, Sensitivity};

fn main() {
    let floor = RedactionFloor::builder()
        .raise("access_token", Sensitivity::High)
        .expect("valid floor rule")
        .build()
        .expect("valid floor");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.floor(floor).allow_exact("access_token");
        })
        .expect("valid field rule")
        .build()
        .expect("valid policy");
    let output = Redactor::new(policy).redact_field("access_token", "raw-token");
    assert_eq!(output.text().as_str(), "****");
}
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

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::{RedactionPolicy, Redactor};

fn main() {
    let mut policy = RedactionPolicy::disabled();
    assert!(policy.is_disabled());
    policy.set_disabled(false);
    let output = Redactor::new(policy).redact_field("password", "raw-secret");
    assert!(!output.summary().is_redaction_disabled());
    assert!(!output.text().as_str().contains("raw-secret"));
}
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

## Budget Units and Migration to 0.8

| Entry point | Structure and input limits | Logical Serde payload | Final encoded bytes |
| --- | --- | --- | --- |
| Fields, domain text, composer, batch | Shared transaction admission per entry point | Not applicable | `max_output_bytes` |
| View or derived source `Serialize` | Shared Serde scope | `max_serde_payload_bytes` | Caller-owned writer |
| `to_json` | Shared Serde scope | `max_serde_payload_bytes` | `max_output_bytes` |
| `redact_json` / `redact_json_value` | Text transaction and JSON-specific limits | Not applicable | `max_output_bytes` |

`max_input_bytes` defaults to 64 KiB; each output-related limit defaults to 16 KiB.
All accept zero. Policy construction rejects Serde payload or final output ceilings above `isize::MAX`.
In 0.8, replace former `batch()` calls with `diagnostic_batch()`. Use `finish()`
for the default diagnostic marker or `finish_with_marker(marker)` for a custom one.
Enable `bigdecimal` explicitly when using BigDecimal; enabling `serde` alone no longer suffices.

Migrate 0.6 configurations that limited direct Serde payloads with `max_output_bytes` to
`max_serde_payload_bytes`. Set both when `to_json` must obey both ceilings; they are never implicitly linked.

Scalar entry points admit the root node, key length, and key UTF-8 bytes before classification
or value formatting. With redaction enabled, High/Secret charges only key bytes and does not invoke value Display.
Capture admits complete write chunks atomically: rejected chunks count as presented but not inspected;
accepted prefixes remain charged even when failure discards all their raw text.
Thus `inspected_input_bytes <= max_input_bytes`, while presented bytes may be larger.
Domain labels, structural nodes, and Serde events have their own admission units; usage is not the
memory size of the original object.

Logical Serde payload counts UTF-8 str/char bytes, byte slices, and numeric/bool scalar representations.
None/unit counts zero; dynamic map keys and scalar unit-variant names count as payload.
Static field names, punctuation, escaping,
and encoder framing do not count. Nested events share the ledger, and ordinary Serialize runs once.
Final `to_json` bytes include all JSON labels, quotes, escapes, punctuation, and masks.
For example, `{"value":"abcd"}` has four logical payload bytes and 16 final JSON bytes.
The caller must bound additional encoding overhead from an arbitrary external serializer.

| Scalar outcome | Completion | Reasons | Later work allowed |
| --- | --- | --- | --- |
| Normal text or fixed mask fits completely | Complete | No degrading reason | Yes, unless exactly full |
| Input rejected; replacement fits | Truncated | InputLimitReached | Yes, subject to admission |
| Formatter itself returns Err; replacement fits | Truncated | FormattingFailed | Yes |
| Either failure's replacement cannot fit | Exhausted | Original cause + OutputLimitReached | No |
| Actual output truncation; replacement fits | Truncated | OutputLimitReached | No |
| Output cannot even retain a replacement | Exhausted | OutputLimitReached | No |

An item failure neither resets the batch budget nor unconditionally closes output; the aggregate
summary remains incomplete. Post-publication helpers such as `finish_with_marker(marker)` and
`text_or_marker` escape the caller's marker, but that marker and caller-added log prefixes/suffixes
are outside the original transaction's `output_bytes` and `max_output_bytes`.
Budgets control library admission and writes, not arbitrary computation inside Display/Serialize or
allocations made before calling the library.

## Errors and Diagnostics

Use `summary().completion()`, `summary().reasons()`, and `summary().usage()`
when the caller needs to distinguish a complete result from a budget or parser
degradation. Do not infer that state by parsing displayed text. For strict
presentation, `complete_text()` and `into_complete_text()` reject an incomplete
result; for diagnostic presentation, `text_or_marker()` and
`into_text_or_marker()` select an explicit fallback. An inspection error means
classification was inconclusive and should be treated as sensitive when the
result controls a security decision.

## Handle Incomplete Results

`RedactionCompletion` distinguishes complete rendering from budget or parser degradation.
Diagnostic callers usually log `text()` or `text_or_marker(fallback)` and inspect
`summary().reasons()` afterward. Audit or storage paths that require completeness should call
`complete_text()` or `into_complete_text()` and handle the error explicitly.

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::{RedactionCompletion, RedactionPolicy, Redactor};

fn main() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(1);
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    let output = Redactor::new(policy).redact_field("password", "raw-secret");
    assert_ne!(output.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(output.text_or_marker("<truncated>"), "<truncated>");
    assert!(output.complete_text().is_err());
}
```

Even when `completion()` is not `Complete`, published text remains confidentiality-safe: the
library emits masks or caller-selected markers instead of partial secrets. Markers passed to
`text_or_marker` or `finish_with_marker` are escaped and are not counted toward the original
transaction `output_bytes`.

## Troubleshooting

| Symptom | Check first | Notes |
| --- | --- | --- |
| Raw secret in output | `summary().is_redaction_disabled()` and the `Redactor` snapshot | Disabled policy restores values by design |
| Unknown field stays visible under standard policy | Switch to `Redactor::strict()` or add field rules | Standard mode intentionally leaves unlisted names plain |
| Unknown field over-masked under strict policy | Add `allow_exact` / `allow_suffix` or use standard policy | Strict mode defaults unknown scalars to secret |
| Truncated or empty batch item | `completion()`, `reasons()`, `usage()` | Earlier batch items consume shared limits |
| Handle shows fallback marker | Handle belongs to a different batch | Handles do not cross batches |
| `complete_text()` fails | Output was truncated or exhausted | Expected for audit paths; use `text_or_marker` for logs |
| Domain field not masked | Derive level, sibling keyed_by field, or manual `Redact` rules | Runtime does not infer business semantics from Rust types |
| JSON key visible | Input used `redact_json_value` vs domain `Redact` | JSON text path classifies keys; domain path uses annotations |
| Inspection panics in tests but not production | Inspection must not format values | Ensure production logging does not bypass redaction entry points |
| URI accepted when it should be rejected | Use `inspect_uri`, not only `redact_uri` | Redaction produces safe text; inspection drives admission |
| HTTP body shows source truncation | `RedactionReason::SourceTruncated` vs output limits | Use the correct `BodyCapture` constructor for partial bodies |

## Concurrency and Runtime Constraints

Each `Redactor` owns an immutable `Arc<RedactionPolicy>` snapshot. Cloning a redactor is cheap and
thread-safe. Composers, batches, and inspection sessions are not shared across threads unless you
externally synchronize them; create one session per diagnostic event.

`Redactor::replace_application_default()` affects only future snapshots from
`application_default()` and generated formatting that re-reads the global default. Existing
redactors, composers, and batches keep the policy they were created with.

The library does not erase source memory, does not intercept arbitrary `println!` or tracing
macros, and does not bound work performed inside user-defined `Display` or `Serialize`
implementations before redaction starts. Wrap external serializers when final encoded size must
be capped separately from logical Serde payload limits.

## Limitations and Best Practices

- Mark fields as sensitive from domain knowledge; `unmarked` and unannotated
  derive fields intentionally remain visible.
- Do not expose `RedactionPolicy::disabled()` to request-controlled inputs; it
  restores raw values and is intended only as a process-wide debugging escape
  hatch.
- This crate protects only calls routed through its runtime. It does not erase
  source memory or protect unrelated logging and serialization paths.

## Further Reading

- [English README](../README.md) · [中文 README](../README.zh_CN.md)
- [API reference for 0.8.0](https://docs.rs/qubit-redact/0.8.0/qubit_redact/)
- [derive guide](../derive/README.md) · [中文用户手册](user_guide.zh_CN.md)
- [Design](design.md) · [中文设计文档](design.zh_CN.md)

From the repository root, run `python3 -B scripts/check_doc_examples.py` to compile
and execute every annotated Rust/Cargo block in both README and guide languages.
The checker uses this checkout as a path dependency, temporary consumer crates,
and offline Cargo resolution; dependencies must already be cached.

To validate a local checkout with the full CI matrix:

```bash
./align-ci.sh
./ci-check.sh
```

The checked-in `.rs-ci-cargo-matrix.json` is consumed by `ci-check.sh` for
`check`, `test` (including doctests), `doc`, and Clippy. It covers minimal format
features, derive consumers with and without Serde/JSON/HTTP/URI, explicit
BigDecimal support, and all features: 28 distinct runtime feature sets after implied
features are expanded, plus the derive crate. README and guide examples use the features
required by each example; URI-only snippets are skipped when `uri` is disabled.
