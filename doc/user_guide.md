# qubit-redact User Guide

[简体中文](user_guide.zh_CN.md) · [README](../README.md) ·
[API documentation](https://docs.rs/qubit-redact)

This guide covers `qubit-redact` 0.5 and Rust 1.94 or later. It is for
application and library authors who need to compose diagnostics from several
data sources without losing a single redaction policy or resource boundary.

## Conceptual Model

Four objects define the normal workflow:

1. `RedactionPolicy` is an immutable snapshot containing field rules, masking
   choices, format policy, and transaction limits.
2. `Redactor` owns an `Arc` snapshot. `standard()` and `strict()` are
   deterministic; `application_default()` is the process-wide snapshot used by
   `Redact::redacted()`.
3. `RedactionSession` is reusable, but its current transaction is private.
   Aggregate operations append composed text; item operations return opaque
   `RedactionHandle` values.
4. `finish()` atomically publishes a `RedactionSessionOutput`, then starts a
   fresh transaction with the same policy. The output contains aggregate text,
   one transaction summary, and the item arena used by `resolve()`.

```text
policy snapshot -> reusable session -> private transaction -> finish()
                                      |                    -> aggregate text
                                      +-> opaque handles   -> resolved items
```

Completion is machine-readable: `Complete`, `Truncated`, or `Exhausted`.
Reasons distinguish input, output, traversal, depth, source-truncation, and
format failures. Usage reports presented and inspected input, retained output,
visited structure, maximum depth, and known or unknown omitted bytes.

## Scenario: One Safe Request-Failure Event

An API client needs one log line containing a request ID and domain value, plus
separate URL and response-body values for telemetry. The success criteria are:

- the access token and password never appear in any published text;
- every fragment shares one output and traversal limit;
- URL and body handles are unreadable until the transaction finishes; and
- the session is reusable for the next request.

## Installation and Minimal Configuration

Enable only the formats that the application uses:

```toml
[dependencies]
qubit-redact = { version = "0.5", features = ["http", "json", "uri"] }
```

Build one immutable policy. Namespace closures update drafts and are applied
only after validation succeeds:

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

`Redactor::strict()` is a useful fail-closed starting point. Use a custom
policy when the application has reviewed which fields may remain visible.

## Core Workflow

### Aggregate text and separately resolved items

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

assert!(!safe_url.text().as_str().contains("raw-token"));
assert!(!safe_body.text().as_str().contains("raw-password"));
assert_eq!(output.summary().usage().output_bytes(),
           output.text().as_str().len()
               + safe_url.text().as_str().len()
               + safe_body.text().as_str().len());

# Ok::<(), qubit_redact::RedactionHandleError>(())
```

Aggregate calls never create item handles, and item calls never append to the
aggregate text. Both still contribute to the transaction summary and budget.
A handle from one transaction returns `DifferentTransaction` when resolved
against another transaction's output.

### Reuse the session

`finish(&mut self)` installs the next transaction immediately:

```rust
use qubit_redact::Redactor;

let mut session = Redactor::strict().session();
let first = session.literal("first").finish();
let second = session.literal("second").finish();

assert_eq!(first.text().as_str(), "first");
assert_eq!(second.text().as_str(), "second");
```

### Domain objects

Every `Redact` implementation must explicitly define `write_redacted`:

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

`unredacted` deliberately bypasses field-name policy. It is suitable only for
content independently reviewed as safe. In derive implementations, an
unannotated field maps to `unredacted`; `#[redact(skip)]` generates no access
or output; `level`, `nested`, `map`, and `json` select their explicit writer
paths. The crate never guesses sensitivity from a field name or value content.

## Advanced Usage

### All six format families

Each family has an aggregate namespace, an item-handle method, and a
`Redactor::redact_*` one-shot convenience path:

| Format | Aggregate namespace | Representative item method |
| --- | --- | --- |
| argv | `session.argv(...)` | `session.redact_argv(items)` |
| env | `session.env(...)` | `session.redact_env(name, value)` |
| process | `session.process(...)` | `session.redact_process(...)` |
| JSON | `session.json(...)` | `session.redact_json(text)` |
| HTTP | `session.http(...)` | `redact_http_url/body/headers` |
| URI | `session.uri(...)` | `session.redact_uri(text)` |

Collection operations produce one handle for the whole collection while every
element still consumes collection and structural accounting. HTTP intentionally
has separate URL, header, and body item methods; there is no ambiguous
multi-operation `redact_http` handle.

### Application default snapshot

`Default for Redactor` always means `standard()` and never reads mutable global
state. To change only the snapshot used by `Redact::redacted()`:

```rust
use qubit_redact::Redactor;

let previous = Redactor::replace_application_default(Redactor::strict());
let current = Redactor::application_default();
let _ = Redactor::replace_application_default(previous);
assert_eq!(current, Redactor::strict());
```

Existing redactors and sessions retain their earlier snapshots. Replacement is
of the complete policy, so readers never observe a mixture of two policies.

### Upstream-truncated HTTP bodies

Use `BodyCapture::truncated(bytes, total_len)` when the source length is known,
or `BodyCapture::truncated_unknown(bytes)` when it is not. The summary includes
`SourceTruncated`; `omitted_input_bytes()` is `None` for unknown length. Never
claim a complete capture when bytes were omitted before redaction.

## Errors and Diagnostics

Policy construction returns `PolicyError` for invalid configuration. Handle
resolution returns only `DifferentTransaction` or `MissingItem`.

Input limits, output limits, structural limits, invalid JSON/URI/content type,
unsupported content, and upstream truncation are safe redaction outcomes rather
than `finish()` errors. Inspect `output.summary()` instead of parsing marker
text. `Exhausted` means even the operation's complete safe substitute could not
fit the shared output budget.

If user-supplied writer or adapter code panics, the active transaction is
discarded, a fresh transaction is installed, and the panic continues. After a
caller catches it with `catch_unwind`, the session is reusable; handles from
the aborted transaction can never resolve.

## Troubleshooting

- Empty item text with `Exhausted`: inspect `OutputLimitReached` and increase
  `max_output_bytes`, or reduce earlier operations in the same transaction.
- `DifferentTransaction`: resolve the handle before discarding the exact
  `RedactionSessionOutput` returned by its `finish()`.
- Unexpected visible data: check for unannotated derive fields and explicit
  `unredacted` calls. Neither path consults runtime field policy.
- Unexpected early truncation: inspect presented versus inspected input,
  visited nodes/items, and `max_depth` in `RedactionUsage`.
- JSON/HTTP/URI methods unavailable: enable the corresponding Cargo feature.

## Limitations and Best Practices

- Treat `literal` as a compile-time program-text API, never as a route for
  runtime input.
- Review every new domain field. Use `skip` only when the field should produce
  neither access nor output.
- Keep one session per independently mutable workflow; share immutable
  `Redactor` policy snapshots where appropriate.
- Size limits for the whole diagnostic event, not for each format in isolation.
- Only text published by `finish()` or returned as `RedactionOutput` is the
  final typed redaction boundary.

## Further Reading

- [README](../README.md)
- [中文用户指南](user_guide.zh_CN.md)
- [API documentation](https://docs.rs/qubit-redact)
- [Transactional architecture](2026-08-19-rs-redact-transactional-redesign-design.md)
