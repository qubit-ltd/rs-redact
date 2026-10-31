# qubit-redact User Guide

[README](../README.md) · [Chinese guide](user_guide.zh_CN.md) · [derive guide](../derive/README.md) · [API reference](https://docs.rs/qubit-redact/0.10/qubit_redact/)

This guide covers **qubit-redact 0.10** and requires **Rust 1.94+**. It is for
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

For application and library authors using qubit-redact 0.10. Start with business serialization
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
qubit-redact = { version = "0.10", features = ["derive", "serde", "json"] }
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
qubit-redact = "0.10"
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
from the previous mask. It supports Display/Debug. Structured view serialization uses the derive-generated
`RedactSerializeSource` projection capability, which borrows data for the current call; callers
need not implement hidden traits. `#[redact(serde)]` separately keeps the source type’s ordinary
`Serialize` path redacted through the legacy `RedactSerialize` bridge, whose bounds are not the
same as the view projection. It never falls back to a Debug string. The legacy hook uses its
explicit policy for a root call, while a bare `RedactSerializeSource` projection does not retain a
policy and returns a value-free serializer error when no scope is active. Use `redact_view()` or
`to_json()` for the normal scoped path. Interior-mutable sources can change
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

Creating a composer starts an independent transaction budget; appended operations consume that
budget cumulatively. `finish(self)` consumes and publishes the transaction without resetting its
budget. Reuse a `Redactor` to create new composers. Finalized `RedactionTextOutput` or `RedactedText`
values can be cached and displayed repeatedly without running redaction again.

## Composer vs Batch

Both share one policy snapshot and one transaction budget, but they answer different questions.

| Model | Publishes | Best for |
| --- | --- | --- |
| `text_composer()` | One concatenated `RedactionTextOutput` | Single log line or error message |
| `diagnostic_batch()` | Per-item handles resolved through `finish_with_marker` | Inspecting parts independently, HTTP URL vs headers vs body |

Batch handles are valid only for the batch that created them. Resolving a handle from an earlier
batch through a later `finish_with_marker` returns the escaped fallback marker, not the original
text. Composers do not expose handles; the entire message succeeds or degrades as one unit. An empty
failed item may share a rejected handle with other failures instead of storing a result slot. The
batch summary still records every rejection reason and its usage, and a rejected item does not prevent
later work while budget remains.

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
| `nested` | Delegate to `Redact`; structured output follows the nested value’s generated view projection, which supports local borrows through its projection capability. |
| `map` | `HashMap`/`BTreeMap` with `String`, `&str`, or `Cow<str>` keys, optionally wrapped in `Option`; values require level capability and `Debug` for pass-through text. |
| `map_key_level = "..."` | Fixed level for each map key; values remain ordinary. |
| `map_key_level = "...", map_value_level = "..."` | Independently fixed key and value levels. |
| `keyed_by = key` | Classify by a sibling `AsRef<str>` key on a named field; value requires level capability and `Debug`. |
| `json` | JSON `String`/`str`/`Cow<str>`, parsed `serde_json::Value`, references and `Option`; requires `json`. |

### Sensitive map keys

Text map redaction supports `HashMap` and `BTreeMap`. Keys and values need the level capability and `Debug` required by the current implementation; keys also need the container's hash or ordering capability. Structured redaction adds `AsRef<str>` for keys and `Serialize` plus level serialization capability for values. A numeric key may work in a text path without being supported in structured output. Leaving `map_value_level` unset means values use ordinary output; it does not remove these type bounds.

When two keys redact to the same key, structured serialization fails. The standard secret mask is fixed text, so two distinct keys are enough to collide; other masks fail too whenever their rendered keys match. Text diagnostics may display duplicate masked keys, which does not imply JSON serialization will succeed. `to_json()` returns no partial JSON on failure. When writing directly through an external serializer or writer, discard failed output and never fall back to serializing the source object.

<!-- redact-example: kind=run features=derive,serde,json -->
```rust
use std::collections::BTreeMap;
use qubit_redact::{Redact, Redactor};

#[derive(Redact)]
struct Labels {
    #[redact(map_key_level = "secret")]
    entries: BTreeMap<String, String>,
}

fn main() {
    let redactor = Redactor::standard();
    let one = Labels {
        entries: BTreeMap::from([("alpha".into(), "one".into())]),
    };
    let encoded = redactor.to_json(&one).expect("one masked key");
    let value: serde_json::Value = serde_json::from_str(&encoded).expect("JSON");
    assert_eq!(value, serde_json::json!({"entries": {"<redacted>": "one"}}));

    let two = Labels {
        entries: BTreeMap::from([
            ("alpha".into(), "one".into()),
            ("beta".into(), "two".into()),
        ]),
    };
    let result = redactor.to_json(&two);
    assert!(result.is_err());
    let diagnostic = result.unwrap_or_else(|_| "<redaction unavailable>".into());
    assert_eq!(diagnostic, "<redaction unavailable>");
}
```

Container attributes: `debug`, `display`, `serde`, `transparent`, and `crate = path`.
The runtime `serde` feature generates structured redaction for `redact_view()` for every
derived type. `#[redact(serde)]` additionally makes the source type's ordinary `Serialize`
use that redacted representation. Without it, a separately derived ordinary `Serialize`
remains unchanged. Enable the runtime `serde` feature; generated implementations do not
require a direct Serde dependency. Add `serde` when your own code uses its traits or derives.
`transparent` requires exactly one field and delegates its representation; it does not declare scalar capability.
For transparent fields, `skip_serializing_if` follows native Serde behavior and is not called: the selected field event is forwarded, including an empty string. If an earlier version emitted `null`, consumers should accept the field representation; non-JSON serializers may also observe a changed event. Redaction-specific `skip` remains separate and still uses a safe replacement while enabled.
Ordinary one-field newtypes also preserve Serde's `newtype_struct` event and ignore the field's `skip_serializing_if`; this avoids replacing an empty value with a unit-struct `null`. If a protocol requires `null`, use an explicit serializer or an `Option` representation. For named fields, a true conditional omission calls the serializer's `skip_field` with the effective wire name; custom serializers can observe this notification and may return an error.
Do not derive ordinary `Debug` together with `debug`, or ordinary `Serialize` together with `serde`.

### Choosing the serialization boundary

With the runtime `serde` feature, `Redact` always generates the redacted projection used by
`redact_view()` and `to_json()`. Nested projections use `RedactSerializeSource` for supported
containers such as Option, Vec, fixed arrays, and tuples. Slice support belongs to explicit level
redaction; it does not provide nested slice projections. Admitted fixed arrays serialize as tuples,
while slices in level mode serialize as sequences. The source type does not need to implement `Serialize` for
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

Self-recursive `nested` edges are supported through containers such as
`Option<Box<Node>>` and `Vec<Box<Node>>`. Child projections are created lazily
while the parent is serialized, so the source type does not need ordinary
`Serialize` just to use `redact_view()` or `to_json()`. The usual field
capability rules still apply; a missing projection capability is reported when
serialization is requested, while text-only redaction remains available.
`to_json()` additionally requires the `json` feature.

For a self-recursive field, derive automatically inserts `nested` when the field
has no `redact` attribute, no custom Serde `with`/`serialize_with` adapter, and
its syntax matches a supported self-recursive shape. An explicit
`#[redact(unmarked)]` is an attribute and therefore opts out; it differs from
leaving the field unannotated. Recognition does not resolve arbitrary type
aliases or arbitrary cross-type recursion graphs. Text derive recognizes
recursion through direct types and supported wrappers such as `Option`, `Box`,
`Vec`, tuples, arrays, and parentheses. The Serde recursive projection has a
narrower set: direct self-recursion, `Option<Box<Self>>`, and `Vec<Box<Self>>`.
Use `#[redact(nested)]` to make the intended behavior explicit when applicable.

<!-- redact-example: kind=run features=derive -->
```rust
use qubit_redact::{Redact, Redactor};

#[derive(Redact)]
struct Node {
    #[redact(level = "secret")]
    password: String,
    next: Option<Box<Node>>,
}

fn main() {
    let value = Node {
        password: "parent-secret".into(),
        next: Some(Box::new(Node { password: "child-secret".into(), next: None })),
    };
    let output = Redactor::standard().redact_text(&value);
    assert!(!output.text().as_str().contains("child-secret"));
}
```

Here `next` is normalized to `nested`, so a child node's `password` remains
redacted. A custom Serde adapter is not normalized automatically; annotate the
field explicitly when the adapter's representation supports nested redaction.

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

Serde names use their effective field and variant names, including `rename`/`rename_all`; raw Rust identifiers are normalized before matching, while an explicit Serde rename preserves its chosen wire name. Enum tag/content/untagged, transparent, skip, skip_serializing, and skip_serializing_if are supported. with/serialize_with work on ordinary or skipped fields, not on sensitive
modes observing raw field state. Generic type or const parameters referenced by
the adapter path, plus predicates transitively required by those parameters, are
retained for its generated carrier; unrelated source parameters are not copied.
flatten is unsupported. JSON text fields retain their string
wire type; parsed Value fields retain JSON structure. Generated Serde adapters follow Serde's
representation events and effective names: transparent types forward the field event, adjacent
tags report the enum name, variant index, and effective variant name, and untagged named variants
report the effective container name. JSON shape is unchanged. The corrected `Some` and fixed-array
Tuple events apply to direct source serialization enabled by `#[redact(serde)]` and borrowed views.
Non-JSON serializers can observe these event changes, so stored data may need its old decoder or an
explicit format version. When migrating, read old data with the old implementation and re-encode it
with the corrected one; do not assume the new event layout decodes old data automatically.
In particular, `Option<Map>::Some` now emits `Some` containing the map. The library does not
automatically decode the earlier layout.
Redact attributes are supported on containers and fields, not enum variants. Variant-level
`#[redact(...)]` is rejected at compile time; put field behavior on that variant's fields, or
remove the attribute from a unit variant.

### Internally Tagged Variants and Newtype Payloads

An internally tagged variant must serialize its payload as a map or struct so the tag can be
added to that object. A nested value whose generated projection is a struct works directly. A
regular tuple newtype wrapper can instead emit Serde's `serialize_newtype_struct` event, which
the internally tagged adapter rejects because it is not itself a map/struct event. This limit
applies to ordinary newtype wrappers; a `transparent` wrapper delegates its field's
representation and is a different representation choice. Use a direct payload or `transparent`
only when that wire representation matches the application's protocol.

The complete example below contrasts the rejected wrapper with a direct struct payload. The
first `to_json()` call must return an error; the second keeps the internal tag and masks the
secret field.

<!-- redact-example: kind=run features=derive,serde,json -->
```rust
use qubit_redact::{Redact, Redactor};

#[derive(Debug, Redact)]
#[redact(serde)]
struct Payload {
    #[redact(level = "secret")]
    password: String,
}

#[derive(Debug, Redact)]
#[redact(serde)]
struct Wrapper(#[redact(nested)] Payload);

#[derive(Debug, Redact)]
#[redact(serde)]
#[serde(tag = "kind")]
enum WrappedEvent {
    V(#[redact(nested)] Wrapper),
}

#[derive(Debug, Redact)]
#[redact(serde)]
#[serde(tag = "kind")]
enum DirectEvent {
    V(#[redact(nested)] Payload),
}

fn main() {
    let redactor = Redactor::standard();
    let wrapped = WrappedEvent::V(Wrapper(Payload { password: "raw-secret".into() }));
    assert!(redactor.to_json(&wrapped).is_err());

    let direct = DirectEvent::V(Payload { password: "raw-secret".into() });
    let json = redactor.to_json(&direct).expect("direct struct payload");
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["kind"], "V");
    assert_eq!(value["password"], "<redacted>");
    assert!(!json.contains("raw-secret"));
}
```

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
| Unannotated fields | No classification; ordinary output, except supported self-recursive fields automatically become nested |
| `unmarked` | No classification; ordinary output, including on self-recursive fields |

Default Low retains two leading and two trailing characters, fully hiding short strings;
Medium retains one trailing character; High emits `****`; Secret emits `<redacted>`.
For example, `abcdef` becomes `ab****ef` at Low and `*******f` at Medium.
Business types choose the correct level; strict policy does not override explicit declarations.

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::MaskingPolicy;
use qubit_redact::Sensitivity;

fn main() {
    let masking = MaskingPolicy::default();
    assert_eq!(masking.mask(Sensitivity::Low, "ab"), "****");
    assert_eq!(masking.mask(Sensitivity::Low, "abcdef"), "ab****ef");
}
```

| Level | Example value | Masked output |
| --- | --- | --- |
| Low | `abcdef` | `ab****ef` |
| Low | `ab` | `****` (short strings fully hidden) |
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

Before a JSON text tree is materialized, a read-only structural preflight
checks syntax and the shared depth/node/item ceilings. If it passes, the unique
decoder performs its own lexical validation and strict tree construction; the
seed then formally charges the shared structural budget once. Preflight does
not consume that budget. This can scan the input more than once: one tree
materialization does not mean one scan, and the parser-entry test counter does
not count scans inside the decoder.

Input bytes are charged when admitted before structural preflight. A rejected
tree adds no shared visited-node or collection-item usage. Node or item
rejection closes traversal for the transaction; a shared depth rejection does
not. When several checks fail, output/input admission takes precedence, then
shared structural preflight, then JSON-specific admission or materialization.
Use completion and reason data in the result summary to understand a partial
result; the exact prefix visited before failure is not a stable contract.
JSON text and `Value` writer admission failures retain the reason already recorded by admission;
they do not add a second traversal reason. If the safe replacement does not fit, actual output
exhaustion can add `OutputLimitReached`.
Serde serialization that has no active scope uses its existing opaque
replacement when this preflight rejects the input.

Invalid JSON and traversal limit failures fail closed as an opaque or
truncated safe result. The borrowed
`Value` path does not clone, stringify, or mutate the caller's value. Within a
domain implementation, `fields.json_value("payload", &value)` writes a parsed
value as JSON rather than as a quoted JSON string. Sequence implementations use
`items.json_value_item(&value)` for the same recursive JSON policy; this matters
for downstream collections whose declared data type is JSON, because each item
must be traversed as JSON instead of formatted as an opaque scalar.

HTTP JSON, NDJSON, and multipart JSON rendering also borrows the structures
admitted for that body operation. Rendering does not build a second masked
`Value` tree or mutate the admitted values; the bounded serializer writes the
redacted result from those borrowed nodes.

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
invalid-JSON path. Duplicate object keys are rejected after JSON string
decoding, so escaped spellings of the same key also conflict. The text decoder applies the configured shared `max_depth` and JSON-specific
`max_json_depth`; it has no additional fixed container cap. When JSON is nested
inside a domain value, its relative depth adds to the active domain depth. This
combined depth is reported by `RedactionUsage::max_depth()` and can cause an
earlier `DepthLimitReached` result than before; raise the shared `max_depth` when
the wrapper structure needs more room. A borrowed `Value` skips raw-text parsing,
so original input-byte limits and duplicate-key detection are unavailable after
parsing. The `arbitrary_precision` feature is enabled only
for a merged-dependency regression test; it does not mean this library accepts
arbitrary-precision JSON numbers. A former serde_json private Number-marker
key is an ordinary object key.

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

Choose the `BodyCapture` constructor that matches what the caller actually
captured:

| Constructor | Source bytes available | Total source length | Use when |
| --- | --- | --- | --- |
| `complete(bytes)` | All bytes | Known: `bytes.len()` | The full body is present. |
| `prefix(bytes, max_bytes)` | Up to `max_bytes` from the supplied complete body | Known | The caller has the complete body and wants to cap the prefix before redaction. |
| `truncated(bytes, total_len)` | A prefix | Known; must exceed `bytes.len()` | The source capture already omitted bytes and the exact total is known. |
| `truncated_unknown(bytes)` | A prefix | Unknown | The source capture omitted bytes and the original total is unavailable. |

Source truncation is exposed as `RedactionReason::SourceTruncated`; output
truncation is separately reported as `OutputLimitReached`. A parsed truncated
body retains the source reason and can report both reasons if output also
exceeds its budget. URL and form output truncation is never reported as
`Complete`. Never construct a complete capture from an incomplete body.

### Configure unkeyed JSON scalars across JSON and HTTP

The root builder setting `unkeyed_json_value_policy` is shared by ordinary JSON
redaction and HTTP JSON bodies, NDJSON records, and JSON parts inside multipart
bodies. It controls only scalar JSON roots and scalar array elements; object
properties continue to use their field rules. The HTTP view's `unkeyed_json`
method changes this same root-level setting. Standard policy preserves unkeyed
scalars; strict policy redacts them unless explicitly configured otherwise.

<!-- redact-example: kind=run features=http -->
```rust
use qubit_redact::formats::http::BodyCapture;
use qubit_redact::{RedactionPolicy, Redactor, UnkeyedJsonValuePolicy};

fn main() -> Result<(), qubit_redact::PolicyError> {
    let policy = RedactionPolicy::strict()
        .to_builder()
        .http(|http| {
            http.unkeyed_json(UnkeyedJsonValuePolicy::PassThrough);
        })?
        .build()?;
    let redactor = Redactor::new(policy);
    let json = redactor.redact_json(r#"["visible",23]"#);
    assert!(json.text().as_str().contains("visible"));
    assert!(!redactor
        .inspect_json(r#"["visible",23]"#)
        .expect("inspection should be conclusive")
        .contains_sensitive());

    let body = redactor.redact_http_body_with_content_type_text(
        BodyCapture::complete(br#"["visible",23]"#),
        Some("application/json"),
    );
    assert!(body.text().as_str().contains("visible"));
    Ok(())
}
```

### Configure URL query and form fields separately

URL query parameters use `http.query()` rules. Form fields in a captured
`application/x-www-form-urlencoded` body use `http.body()` rules:

<!-- redact-example: kind=run features=http -->
```rust
use http::HeaderValue;
use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};
use qubit_redact::formats::http::BodyCapture;

fn main() -> Result<(), qubit_redact::PolicyError> {
    let policy = RedactionPolicy::builder().http(|http| {
        http.query()
            .raise("custom_query_probe", Sensitivity::Secret)
            .expect("valid query rule");
        http.body()
            .raise("custom_form_payload", Sensitivity::Secret)
            .expect("valid body rule");
    })?.build()?;
    let redactor = Redactor::new(policy);

    let url = redactor.redact_http_url(
        "https://example.test/?custom_query_probe=query-secret&custom_form_probe=query-visible",
    );
    assert!(!url.text().as_str().contains("query-secret"));
    assert!(url.text().as_str().contains("query-visible"));

    let content_type = HeaderValue::from_static("application/x-www-form-urlencoded");
    let body = redactor.redact_http_body(
        BodyCapture::complete(
            b"custom_query_probe=form-visible&custom_form_payload=form-secret",
        ),
        Some(&content_type),
    );
    assert!(body.text().as_str().contains("form-visible"));
    assert!(!body.text().as_str().contains("form-secret"));
    Ok(())
}
```

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

### Use the mandatory URI boundary

`Redactor` is a general redaction entry point, and a disabled application policy
is a raw-value debugging escape hatch there. Use `UriRedactionBoundary` when
URI admission must keep confidentiality enabled regardless of the application
policy. It adds the standard URI field floor and uses standard masks while
retaining application floors, resource limits, and path/fragment settings.
The field floor does not require every path or fragment to be hidden.

For admission, inspect the URI: sensitive results and errors both mean reject.
A successful inspection is not a URI syntax validity certificate. For
diagnostics, use the rendered output only when it is complete; otherwise use a
fixed marker and never fall back to the original URI.

<!-- redact-example: kind=run features=uri -->
```rust
use qubit_redact::RedactionPolicy;
use qubit_redact::formats::uri::UriRedactionBoundary;

fn may_accept(boundary: &UriRedactionBoundary, text: &str) -> bool {
    match boundary.inspect_uri(text) {
        Ok(inspection) => !inspection.contains_sensitive(),
        Err(_) => false,
    }
}

fn main() {
    let boundary = UriRedactionBoundary::new(&RedactionPolicy::disabled());
    assert!(!boundary.policy().is_disabled());
    let uri = "https://example.test/?password=raw-secret";
    assert!(!may_accept(&boundary, uri));
    let output = boundary.redact_uri(uri);
    let text = output.text_or_marker("<uri unavailable>");
    assert!(!text.contains("raw-secret"));
}
```

### Redact argv, environment, and process diagnostics

Explicitly classified argv is preferable when the caller knows the argument
contract. Heuristic argv recognizes supported option forms but is not a shell
parser and does not validate complete command-line syntax.

| argv form | Heuristic behavior |
| --- | --- |
| `NAME=value` | Classifies `NAME` using field rules. |
| `--name=value` | Classifies `name` and processes its inline value. |
| `-Dname=value` | Treats this as a JVM property and classifies `name`. |
| `--name value` | A sensitive option establishes a pending classification for the next item. |
| `-name value` | A single-dash option uses exact field matching. |
| `-pCOMPACT` | Does not split compact options from values; standard policy may preserve the whole item. |
| Items after `--` | `--` does not stop heuristic classification; later supported forms continue to be processed. |

Heuristic processing works on argv elements, not complete CLI syntax. For a known
sensitive compact argument, mark the entire item explicitly with
`ArgvItem::sensitive`. With redaction enabled, heuristic argv mode treats
unclassified non-Unicode arguments as
Secret. Explicit argv mode preserves `ArgvItem::plain` values using lossy
Unicode conversion; mark sensitive values explicitly or select heuristic mode.
Non-Unicode OS arguments include invalid UTF-8 on Unix and unpaired UTF-16
surrogates on Windows.
Non-UTF-8 environment names are conservatively treated as Secret and do not by
themselves make inspection fail. Environment inspection classifies sensitivity
from the name under the selected policy. It counts a non-UTF-8 value for
admission without predicting the renderer's opaque Secret mask for that value;
disabled inspection bypasses name classification. A disabled policy restores
values under its existing contract. Process redaction applies heuristic argv
rules to its arguments, rather than the explicit `redact_argv` behavior.
A trailing sensitive option with no following value remains pending; it is not
reported as a syntax error. Inspection errors report incomplete admission, such
as a shared resource limit.

<!-- redact-example: kind=run features=none -->
```rust
use std::ffi::OsStr;

use qubit_redact::{Redactor, Sensitivity};
use qubit_redact::formats::argv::ArgvItem;

fn main() {
    let arguments = [
        ArgvItem::plain(OsStr::new("--server=example.test")),
        ArgvItem::sensitive(OsStr::new("-pCOMPACT"), Sensitivity::Secret),
    ];
    let variables = [(OsStr::new("PASSWORD"), OsStr::new("raw-password"))];
    let output = Redactor::standard().redact_process(OsStr::new("client"), arguments, variables);
    assert!(!output.text().as_str().contains("COMPACT"));
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

An explicit derive level remains fixed under strict mode. A hand-written
`fields.sensitive_at_least(level, ...)` is a minimum: the final level is the
stronger of that minimum and the runtime classification, so strict can raise it.

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::{Redact, RedactionWriter, Redactor, Sensitivity};

struct Metric { value: String }

impl Redact for Metric {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Metric", |fields| {
            fields.sensitive_at_least(Sensitivity::Low, "custom_metric", || &self.value);
        });
    }
}

fn main() {
    let output = Redactor::strict().redact_text(&Metric { value: "raw-value".into() });
    assert!(!output.text().as_str().contains("raw-value"));
    assert!(output.text().as_str().contains("<redacted>"));
}
```

Strict mode can classify runtime fields such as `redact_field`, JSON keys, and
HTTP URL query parameters. Form fields in `application/x-www-form-urlencoded`
bodies use the HTTP body rules instead. A form field nested inside a multipart part
uses depth 3, so a policy must allow at least that depth; inspection and rendering
use the same boundary and do not raise the configured limit. Multipart framing is
validated before processing, while auxiliary segment storage grows with admitted
parts rather than every segment. Admitted JSON and NDJSON values are retained and reused during
rendering.
Opaque multipart parts such as `application/octet-stream` do not need UTF-8 decoding and render
with the existing opaque marker, so a binary part does not make a neighboring text part disappear.
Sensitive non-UTF-8 parts use the configured opaque mask for their effective sensitivity level.

## Advanced Usage

### Inspect decisions and control policies

Inspection returns whether policy evaluation was disabled, the highest
sensitivity found by the complete traversal, and resource usage, without
publishing raw values. It does not include a per-field rule-match trace. Use
`RedactionPolicy::classify_field()` to inspect the first matching application
rule for a field; that explanation is not the final sensitivity. The effective
level comes from `RedactionPolicy::sensitivity_for()`, which also combines
matching application rules and the configured floor.

Inspection never invokes `Debug`, `Display`, or `Serialize` on classified values. A formatter that
panics during rendering would still allow inspection to complete, provided inspection itself stays
within its structural and input budgets. An incomplete inspection returns an error; treat it as
inconclusive when making a security decision.

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

Scalar `inspect_field(field, value)` admits its root node and the raw UTF-8
bytes of `field` before charging the key and value bytes or classifying the
field. A structural or key rejection therefore returns an inspection error
without classifying the value. These structural limits still apply when the
policy is disabled. For JSON inside a domain value, the JSON root begins one
level below the current domain depth, and its relative depth contributes to the
shared `max_depth`. For example, domain depth 2 plus JSON depth 2 reports usage
depth 4; a limit of 3 rejects inspection with `DepthLimitReached`. Raising the
shared limit restores the previous output depth. JSON-specific `max_json_depth`
remains relative to the JSON root and rejects with `TraversalLimitReached`.

Build one immutable policy and share the resulting `Redactor`. Builder methods
that accept configuration closures consume the builder. If a field rule is
invalid, they return `PolicyError` without returning a replacement builder or
publishing an invalid policy.

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
| `secret_sensitive(name)` | Classify a field as secret using the policy's current matching mode; the default is `ExactOrTokenSuffix` |
| `raise(name, level)` | Raise runtime classification to at least the given level |
| `allow_exact(name)` | Declare an exact-name exception for the normalized complete name |
| `allow_suffix(name)` | Declare an exception that can match exact and semantic token-suffix candidates |
| `floor(floor)` | Install a minimum redaction floor for matching names |

A floor can raise sensitivity above an allow rule when both match the same name. Floors are useful
for provider-specific tokens that must never appear verbatim even if an allow list would otherwise
permit the field. `classify_field()` explains the first matching application rule; it does not apply
floors or combine all matching sensitivities. Use `sensitivity_for()` for the final effective level,
which takes the strongest matching application and floor sensitivity.

`FieldNameMatching::Exact` compares the complete normalized name: matching trims surrounding
whitespace, ignores case, and removes supported separators, so it does not mean byte-for-byte
equality. The default `ExactOrTokenSuffix` also checks semantic token suffixes (such as `pin` in
`user_pin` and `userPin`), not arbitrary string endings. The application's `matching` mode controls
which candidates are visited for both sensitivity and allow rules. Thus `allow_suffix("diagnostic")`
allows `diagnostic` in either mode, but allows `request_diagnostic` only with `ExactOrTokenSuffix`;
with `Exact`, the unknown-field fallback still applies. `allow_exact` never allows a prefixed name.
`AllowRule::matching()` reports the breadth declared by the rule, not an override of the application's
candidate mode. `classify_field()` reports the matching application rule (or `Unknown` when only the
unknown-field fallback applies), while `sensitivity_for()` reports the final effective sensitivity.

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::FieldNameMatching;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;

fn main() {
    for (mode, suffix_level) in [
        (FieldNameMatching::ExactOrTokenSuffix, Some(Sensitivity::Secret)),
        (FieldNameMatching::Exact, None),
    ] {
        let policy = RedactionPolicy::builder()
            .fields(|fields| { fields.secret_sensitive("pin").matching(mode); })
            .expect("fields")
            .build()
            .expect("policy");
        assert_eq!(policy.sensitivity_for("pin"), Some(Sensitivity::Secret));
        assert_eq!(policy.sensitivity_for("user_pin"), suffix_level);
        assert_eq!(policy.sensitivity_for("userPin"), suffix_level);
        assert_eq!(policy.sensitivity_for(" PIN "), Some(Sensitivity::Secret));
    }
}
```

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
| View or derived source `Serialize` | Shared Serde scope; JSON-specific limits checked per `#[redact(json)]` `Value` field | `max_serde_payload_bytes` | Caller-owned writer |
| `to_json` | Shared Serde scope; JSON-specific limits checked per `#[redact(json)]` `Value` field | `max_serde_payload_bytes` | `max_output_bytes` |
| `redact_json` / `redact_json_value` | Text transaction and JSON-specific limits | Not applicable | `max_output_bytes` |

`max_input_bytes` defaults to 64 KiB; each output-related limit defaults to 16 KiB.
All accept zero. Policy construction rejects Serde payload or final output ceilings above `isize::MAX`.
`max_key_bytes` bounds domain field names and supported non-JSON format classification keys;
`max_json_key_bytes` independently bounds decoded JSON object-key UTF-8 bytes. Configure both
when both scopes need limits. JSON text, borrowed `Value`, and HTTP JSON use the JSON limit;
URI and form keys use the general limit.
Sibling keys used only for `keyed_by` classification are admitted against
`max_key_bytes` and do not accumulate into `max_input_bytes`; if the sibling is
also serialized as an ordinary field, that output operation is charged under its
own existing limits. Dynamic map keys are separate Serde payload events and are
counted there.
In 0.8, replace former `batch()` calls with `diagnostic_batch()`. Use `finish()`
for the default diagnostic marker or `finish_with_marker(marker)` for a custom one.
Enable `bigdecimal` explicitly when using BigDecimal; enabling `serde` alone no longer suffices.

Migrate 0.6 configurations that limited direct Serde payloads with `max_output_bytes` to
`max_serde_payload_bytes`. Set both when `to_json` must obey both ceilings; they are never implicitly linked.

For a derived `#[redact(json)]` field stored as `serde_json::Value`, JSON-specific limits
(`max_json_depth`, nodes, collection items, key/string/number bytes, and JSON payload bytes)
are checked against that field's complete tree. They are not accumulated across JSON fields.
When the policy is disabled, this added JSON-specific check is skipped; the existing general
Serde scope accounting and final output limits still apply.
These general limits accumulate in the active Serde scope across the serialized value. Each
projected `Option` layer, whether `Some` or `None`, contributes one structural node and one depth
level. In disabled mode, JSON text string leaf nodes still count toward shared structure and depth,
while JSON-specific limits are skipped. An explicit Display
scalar must pass structural admission before its formatter runs. Rejection uses the existing safe
structural replacement or returns the serializer error required by other limits. Disabled policy
still enforces structural limits. Applications that need the full value should size `max_nodes`
and `max_depth` for the actual projection shape; disabling redaction does not bypass those limits.
Recursive `skip_serializing_if` predicates may refer to the source type as `Self`; derive resolves
that path against the source type, including recursive view projections.
A JSON `String` field is serialized as a string; a `Value` field keeps
its JSON wire structure. `to_json` also enforces the final encoded-byte limit. Directly
serializing a view or source object leaves final encoding size to the external serializer and
writer. A borrowed `Value` has no recoverable original input bytes and cannot reveal duplicate
keys that were discarded while parsing it.

Scalar entry points admit the root node, key length, and key UTF-8 bytes before classification
or value formatting. With redaction enabled, High/Secret charges only key bytes and does not invoke value Display.
Capture admits complete write chunks atomically: rejected chunks count as presented but not inspected;
accepted prefixes remain charged even when failure discards all their raw text.
Thus `inspected_input_bytes <= max_input_bytes`, while presented bytes may be larger.
Explicit Low/Medium `Display` values are formatted once under the shared input-byte allowance;
their accepted UTF-8 prefix remains charged after formatter failure. High/Secret and inspection
do not evaluate the source formatter. Disabled policies still charge explicitly selected text values.
Domain labels, structural nodes, and Serde events have their own admission units; usage is not the
memory size of the original object.

Logical Serde payload counts UTF-8 str/char bytes, byte slices, and numeric/bool scalar representations.
None/unit counts zero; dynamic map keys and scalar unit-variant names count as payload.
When `collect_str` formatting fails, input usage still includes its accepted prefix; the Serde payload
budget counts only scalar content successfully forwarded to the downstream serializer.
Static field names, punctuation, escaping,
and encoder framing do not count. Nested events share the ledger, and each logical scalar payload is
charged once even when a nested redacted value forwards it through another budget adapter. Ordinary
Serialize runs once.

Recursive `Vec` projections admit the container node and the cumulative item count before starting the
sequence. A rejected container is replaced as a whole; insufficient item allowance returns a serializer
error before any vector element callback runs. Directly serializing through an external serializer may
have written a prefix before an error, so the caller must discard or otherwise treat that output as
failed. `to_json` returns a `String` only after complete encoding and never exposes partial JSON.

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

Controlled item failures such as input or output budget limits, parse failures, or a formatter
returning an error neither reset the batch budget nor unconditionally close output; the aggregate
summary remains incomplete. If user code invoked by a batch operation panics and unwinds, the entire
unpublished batch is reset: previously issued handles become invalid, and earlier text, usage, and
summary are discarded. After catching the panic, discard old handles before reusing the batch; its
new summary does not include events from before the reset. This recovery requires unwinding and does
not apply with `panic = "abort"`. Post-publication helpers such as `finish_with_marker(marker)` and
`text_or_marker` escape the caller's marker, but that marker and caller-added log prefixes/suffixes
are outside the original transaction's `output_bytes` and `max_output_bytes`.
Budgets control library admission and writes, not arbitrary computation inside Display/Serialize or
allocations made before calling the library.

## Errors and Diagnostics

Use `summary().completion()`, `summary().reasons()`, and `summary().usage()`
when the caller needs completeness, observed causes, or resource use. A
`Complete` result can carry a parsing reason when a complete safe replacement
was produced; `complete_text()` does not certify that the source syntax was
valid. Do not infer state by parsing displayed text. For strict presentation,
`complete_text()` and `into_complete_text()` reject only `Truncated` or
`Exhausted`; for diagnostic presentation, `text_or_marker()` and
`into_text_or_marker()` select an explicit fallback. An inspection error means
classification was inconclusive and should be treated as sensitive when the
result controls a security decision.

## Handle Incomplete Results

`RedactionCompletion` reports whether the safe representation is complete. It does not report
whether the source syntax was valid: a complete safe replacement can carry `InvalidUri` or
another parsing reason. Diagnostic callers can inspect both `completion()` and `reasons()`.
Audit or storage paths that require complete output should call `complete_text()` or
`into_complete_text()` and handle the error explicitly; callers that require valid input should
use format inspection or check the relevant parsing reason.

The following executable example documents existing behavior for an invalid URI. It does not
add parsing behavior: the safe replacement is complete, while inspection rejects the input.

<!-- redact-example: kind=run features=uri -->
```rust
use qubit_redact::{RedactionCompletion, RedactionReason, Redactor};

fn main() {
    let r = Redactor::standard();
    let invalid = r.redact_uri("");
    assert_eq!(invalid.summary().completion(), RedactionCompletion::Complete);
    assert!(invalid.summary().reasons().contains(RedactionReason::InvalidUri));
    assert_eq!(invalid.complete_text().unwrap().as_str(), "<invalid URI>");
    assert_eq!(invalid.text_or_marker("FALLBACK"), "<invalid URI>");
    assert!(r.inspect_uri("").is_err());
}
```

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

When redaction is enabled, fields the selected policy requires hiding do not fall back to their
untreated original values solely because a result is incomplete. Output may still contain content
the policy allows, including edges retained by a custom mask. Disabled mode may expose original
values in complete or truncated output. `completion()` describes completion, not confidentiality;
check `is_redaction_disabled()` and make sure the selected policy meets your requirements. Markers
passed to `text_or_marker` or `finish_with_marker` are escaped and are not counted toward the
original transaction `output_bytes`.

## Troubleshooting

| Symptom | Check first | Notes |
| --- | --- | --- |
| Raw secret in output | `summary().is_redaction_disabled()` and the `Redactor` snapshot | Disabled policy restores values by design |
| Unknown field stays visible under standard policy | Switch to `Redactor::strict()` or add field rules | Standard mode intentionally leaves unlisted names plain |
| Unknown field over-masked under strict policy | Add `allow_exact` / `allow_suffix` or use standard policy | Strict mode defaults unknown scalars to secret |
| Truncated or empty batch item | `completion()`, `reasons()`, `usage()` | Earlier batch items consume shared limits |
| Handle shows fallback marker | Handle belongs to a different batch | Handles do not cross batches |
| `complete_text()` fails | Output was truncated or exhausted | It checks completion; use `reasons()` or inspection to assess source validity |
| Domain field not masked | Derive level, sibling keyed_by field, or manual `Redact` rules | Runtime does not infer business semantics from Rust types |
| Sensitive JSON field value remains visible | Check whether the input uses `redact_json` / `redact_json_value` or a domain `Redact` implementation | Both JSON entry points preserve keys and classify values by key; domain objects rely on annotations or a manual implementation |
| Inspection does not panic in tests, but production logs still expose raw values | Inspection does not invoke value formatters | Ensure production logging does not bypass redaction entry points |
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
- [API reference for 0.10](https://docs.rs/qubit-redact/0.10/qubit_redact/)
- [derive guide](../derive/README.md) · [中文用户手册](user_guide.zh_CN.md)
- [Design](design.md) · [中文设计文档](design.zh_CN.md)

From the repository root, run `python3 -B scripts/check_doc_examples.py` to compile
and execute every annotated Rust/Cargo block in both README and guide languages.
The checker uses this checkout as a path dependency and builds temporary consumer crates. It runs `cargo run --quiet`; Cargo may access the registry to resolve or download uncached dependencies. Provide registry access when needed; the checker does not force offline resolution. For each Rust block it uses the nearest earlier Cargo block in the same document with the same feature set. If none exists, runner fixtures supply its dependencies; PASS output identifies that source.
The project CI hook runs its wiring tests, the checker tests, and this annotated-example runner.

To validate a local checkout with the full CI matrix:

```bash
./.infra/bin/align-ci.sh
./.infra/bin/ci-check.sh
```

The checked-in `.infra/ci/cargo-matrix.json` is consumed by `.infra/bin/ci-check.sh` for
`check`, `test` (including doctests), `doc`, and Clippy. It covers minimal format
features, derive consumers with and without Serde/JSON/HTTP/URI, explicit
BigDecimal support, and all features: 28 distinct runtime feature sets after implied
features are expanded, plus the derive crate. README and guide examples use the features
required by each example; URI-only snippets are skipped when `uri` is disabled.
