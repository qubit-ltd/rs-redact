# qubit-redact

Rule-driven redaction for scalar fields, command arguments, environment pairs,
JSON, HTTP, URI, and Rust domain values.

## Direct operations

Direct adapters are independent operations and return owned results. They do
not share input/output byte counters:

```rust
use qubit_redact::Redactor;

let redactor = Redactor::standard();
let output = redactor.redact_field("password", "secret");
assert_eq!(output.as_str(), "<redacted>");

let url = redactor.http().redact_url_str("https://example.test/?token=secret");
assert!(!url.as_str().contains("secret"));
```

## Atomic sessions

Use a session only to publish several named adapter results atomically. Each
staged value is prepared independently and `finish` either publishes the whole
batch or rejects it:

```rust
use std::ffi::OsStr;
use qubit_redact::formats::argv::ArgvItem;
use qubit_redact::Redactor;

let redactor = Redactor::standard();
let mut session = redactor.session();
session.argv(|argv| { argv.redact_items("argv", [ArgvItem::plain(OsStr::new("client"))]); });
let committed = session.finish().expect("the batch is valid");
assert!(committed.get("argv").is_some());
```

`RedactionOutput` exposes `text()`, `summary()`, `into_text()`, and
`into_parts()`. Completion is either `Complete` or `Truncated`; summaries retain
structural, parsing, and source-capture reasons.

## Domain and derive

Implement `Redact` or derive it with `qubit-redact-derive`. Nested values are
rendered through the writer-owned traversal context, so every top-level view has
an independent structural budget and cannot leak raw sensitive values.

## Safety model

Structural limits come from `qubit-budget`. JSON value limits are used for JSON
decoding and traversal. HTTP `BodyCapture` reports source length and ingress
truncation; it does not impose a policy-wide byte counter. Destination writers
own any presentation ceiling explicitly.

## License

Apache-2.0.
