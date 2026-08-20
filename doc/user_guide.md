# qubit-redact User Guide

[中文用户指南](user_guide.zh_CN.md) · [README](../README.md) · [API documentation](https://docs.rs/qubit-redact)

This guide covers `qubit-redact` 0.5 on Rust 1.94 or later. It is for Rust
application and library authors who need to assemble diagnostic data from more
than one source without giving every source an independent chance to reveal a
secret or exceed the event budget.

## Purpose and Audience

Use this crate when a diagnostic event contains trusted program text alongside
untrusted fields, domain values, command lines, JSON, HTTP data, or URIs.
Build a policy once, create a session for each independently mutable event, and
publish only its completed output. If you only need a one-off value, the
`Redactor::redact_*` methods create and finish that transaction for you.

## Conceptual Model

Four objects define the normal path:

1. `RedactionPolicy` is an immutable snapshot of field rules, masking, format
   behavior, and resource limits.
2. `Redactor` shares that snapshot and creates sessions. `standard()` and
   `strict()` are fixed policies; `application_default()` is the snapshot used
   by `Redact::redacted()`.
3. `RedactionSession` owns one private, mutable transaction. Aggregate calls
   append to its event text; item calls return opaque `RedactionHandle` values.
4. `finish()` publishes `RedactionSessionOutput`: aggregate text, a
   `RedactionSummary`, and the item arena used to resolve handles. It also
   starts the session's next transaction with the same policy.

```text
policy snapshot -> reusable session -> private transaction -> finish()
                                      |                    -> aggregate text
                                      +-> opaque handles   -> resolved items
```

The summary records completion (`Complete`, `Truncated`, or `Exhausted`),
reasons, and resource usage. Treat it as the programmatic account of safe
degradation; do not infer state by parsing replacement text.

## Scenario: One Safe Request-Failure Event

An API client must emit `request_id` in a human-readable failure message and
send the request URL and JSON error body to telemetry. `access_token` and
`password` must not appear in either published result. All fragments must share
one input, output, and traversal budget. The URL and body remain unreadable
until the event is complete.

## Installation and Minimal Configuration

Enable the integrations the scenario uses:

```toml
[dependencies]
qubit-redact = { version = "0.5", features = ["http", "json", "uri"] }
```

Policies are immutable after `build()`. Namespace closures operate on drafts,
so an invalid configuration returns `PolicyError` without partially changing
the builder:

```rust
use qubit_redact::RedactionPolicy;

let policy = RedactionPolicy::builder()
    .fields(|fields| {
        fields
            .secret_sensitive("password")
            .secret_sensitive("access_token");
    })?
    .limits(|limits| {
        limits
            .max_input_bytes(64 * 1024)
            .max_output_bytes(16 * 1024)
            .max_nodes(1024)
            .max_collection_items(256)
            .max_depth(32);
    })?
    .build()?;

# Ok::<(), qubit_redact::PolicyError>(())
```

`Redactor::strict()` is the appropriate starting point when unknown scalar
fields must be masked. Use a custom policy only after deciding which fields may
remain visible.

## Core Workflow

### Build the event and resolve item results

Aggregate operations return `&mut RedactionSession`; item operations return a
handle. Neither form publishes text before `finish()`.

```rust
use http::HeaderValue;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

# let policy = RedactionPolicy::strict();
let mut session = Redactor::new(policy).session();
let url = session.redact_http_url(
    "https://api.example.test/users?access_token=raw-token",
);
let content_type = HeaderValue::from_static("application/json");
let body = session.redact_http_body(
    BodyCapture::complete(br#"{"password":"raw-password"}"#),
    Some(&content_type),
);
session
    .literal("request failed: ")
    .field("request_id", "req-42");

let output = session.finish();
let safe_url = output.resolve(url)?;
let safe_body = output.resolve(body)?;

assert_eq!(output.text().as_str(), "request failed: <redacted>");
assert_eq!(
    safe_url.text().as_str(),
    "https://api.example.test/<redacted>?access_token=%3Credacted%3E",
);
assert_eq!(safe_body.text().as_str(), r#"{"password":"<redacted>"}"#);
assert_eq!(output.summary().usage().output_bytes(),
           output.text().as_str().len()
               + safe_url.text().as_str().len()
               + safe_body.text().as_str().len());

# Ok::<(), qubit_redact::RedactionHandleError>(())
```

Aggregate text and handle items use the same transaction accounting, but they
are intentionally separate outputs. Resolving a handle with another event's
output returns `DifferentTransaction`.

### Reuse the session

Finishing an event immediately installs the next transaction:

```rust
use qubit_redact::Redactor;

let mut session = Redactor::strict().session();
let first = session.literal("first").finish();
let second = session.literal("second").finish();

assert_eq!(first.text().as_str(), "first");
assert_eq!(second.text().as_str(), "second");
```

Keep a session local to one mutable workflow. Share `Redactor` values and their
immutable policy snapshots instead.

### Describe domain values explicitly

Implement `Redact` to declare how a domain type is traversed. The writer never
guesses whether a field is sensitive:

```rust
use qubit_redact::Redact;
use qubit_redact::RedactionWriter;
use qubit_redact::Sensitivity;

struct Account {
    name: String,
    password: String,
}

impl Redact for Account {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Account", |fields| {
            fields.unredacted("name", || self.name.as_str());
            fields.sensitive(Sensitivity::Secret, "password", || {
                self.password.as_str()
            });
        });
    }
}
```

`unredacted` bypasses field-name policy and therefore requires independent
review. `sensitive` sets an explicit minimum sensitivity. `nested` delegates
to another `Redact` value, and `json` follows the active JSON policy. Use
`skip` only for fields that must be neither accessed nor emitted.

## Advanced Usage

### Format families and one-shot operations

Every family uses the same transaction runtime. Sessions expose aggregate
namespaces and item methods; `Redactor::redact_*` provides a one-shot path.

| Format | Aggregate namespace | Representative item method |
| --- | --- | --- |
| argv | `session.argv(...)` | `session.redact_argv(items)` |
| environment | `session.env(...)` | `session.redact_env(name, value)` |
| process | `session.process(...)` | `session.redact_process(...)` |
| JSON | `session.json(...)` | `session.redact_json(text)` |
| HTTP | `session.http(...)` | `redact_http_url/body/headers` |
| URI | `session.uri(...)` | `session.redact_uri(text)` |

Collection operations create one handle for the collection while each element
still consumes collection and structural accounting. HTTP keeps URL, headers,
and body as deliberately distinct item operations.

### Application default snapshot

`Default for Redactor` always means `standard()`. To change the snapshot used
by `Redact::redacted()`, replace the complete redactor atomically:

```rust
use qubit_redact::Redactor;

let previous = Redactor::replace_application_default(Redactor::strict());
let current = Redactor::application_default();
let _ = Redactor::replace_application_default(previous);
assert_eq!(current, Redactor::strict());
```

Existing redactors and sessions retain their previous snapshots. Readers see a
complete old policy or a complete new policy, never a mixture.

### Report upstream truncation honestly

When an HTTP body was shortened before it reaches this crate, use
`BodyCapture::truncated(bytes, total_len)` if the original size is known, or
`BodyCapture::truncated_unknown(bytes)` otherwise. The summary then reports
`SourceTruncated`; `omitted_input_bytes()` is `None` when the omitted size is
unknown.

## Errors and Diagnostics

Policy construction can return `PolicyError`. Resolving a handle can return
`DifferentTransaction` or `MissingItem`.

Input/output/structural limits, invalid JSON or URI, unsupported content,
invalid content type, and upstream truncation are safe redaction outcomes, not
`finish()` errors. Inspect `output.summary()` for their completion and reasons.
`Exhausted` means the full safe substitute cannot fit the shared output budget;
later item calls return the canonical empty exhausted item without inspecting
their inputs.

If a user-supplied writer or adapter panics, the active transaction is
discarded, a fresh one is installed, and the panic continues. After
`catch_unwind`, the session is reusable, but handles from the aborted event
cannot resolve.

## Troubleshooting

- **An item is empty and exhausted.** Inspect `OutputLimitReached`; increase
  `max_output_bytes` or reduce earlier output in that event.
- **`DifferentTransaction` is returned.** Resolve the handle using the exact
  `RedactionSessionOutput` returned by the `finish()` that followed its call.
- **Cleartext is visible unexpectedly.** Inspect explicit `unredacted` calls
  and unannotated derived fields; neither is corrected by runtime field rules.
- **Output truncates too early.** Compare presented and inspected input,
  visited nodes/items, and maximum depth in `RedactionUsage` with the limits.
- **A JSON, HTTP, or URI API is missing.** Enable its corresponding Cargo
  feature.

## Limitations and Best Practices

- Pass only program-authored `&'static str` text to `literal`; dynamic text
  must enter a redaction operation.
- Review each new domain field and every use of `unredacted`.
- Size limits for the entire diagnostic event, including separately resolved
  items.
- Consider only text from `finish()` or a returned `RedactionOutput` to be the
  final typed redaction boundary.

## Further Reading

- [README](../README.md)
- [中文用户指南](user_guide.zh_CN.md)
- [API documentation](https://docs.rs/qubit-redact)
- [Transactional architecture](2026-08-19-rs-redact-transactional-redesign-design.md)
