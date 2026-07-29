# Qubit Redact User Guide

Qubit Redact is a policy-driven Rust library for preventing sensitive values from
leaking through diagnostics: structured fields and maps, Rust domain objects,
process arguments, environment variables, and optional HTTP data.

## What it solves

Secrets commonly leak through error logs, debug dumps, and serialized
diagnostics, not through the authentication code that received them. Replacing
strings at individual log calls is easy to omit and hard to review. Qubit Redact
centralizes that decision in an immutable `RedactionPolicy`.

This complete program keeps the original secret unchanged and masks the
diagnostic value.

```toml
[dependencies]
qubit-redact = "0.3"
```

```rust
use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = RedactionPolicy::builder()
        .raise("api_key", Sensitivity::Secret)
        .build()?;
    let raw = "sk_live_123";
    let diagnostic = Redactor::new(policy).redact("api_key", raw);

    assert_eq!(raw, "sk_live_123");
    assert_eq!(diagnostic.as_str(), "<redacted>");
    Ok(())
}
```

## Installation and example requirements

The package is `qubit-redact` and Rust imports it as `qubit_redact`. The default
feature set has no runtime dependencies. Add the derive crate for domain
objects, enable `serde` for redacted serialization, and enable `http` for HTTP
diagnostics. Each Rust block is a complete `main.rs`; use the dependency block
shown by its section and run `cargo run`.

```toml
[dependencies]
qubit-redact = { version = "0.3", features = ["serde", "http"] }
qubit-redact-derive = "0.3"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
http = "1.4"
```

## Core concepts

A `RedactionPolicy` is an immutable snapshot of field rules, matching behavior,
masks, and diagnostic budgets. A field is **Sensitive**, **Allowed** by an
explicit exception, or **Unknown** and preserved. `Redactor` owns one snapshot
and applies it consistently.

`RedactedText` means field-sensitive redaction occurred. It intentionally does
not implement `Display`: call `escape_for_log()` before a plain-text log
boundary to obtain `LogSafeText`.

## 1. Configure `RedactionPolicy`

`RedactionPolicy::builder()`, `RedactionPolicyBuilder::new()`, and
`RedactionPolicyBuilder::default()` start with no sensitive or allow rules.
`RedactionPolicy::default()` remains the conservative process-wide snapshot.
`Redactor::default()` uses that snapshot.
Use `RedactionPolicy::builder_from_default()` to extend that snapshot.
`.load_default()` replaces every earlier builder setting, including a recorded
validation error, so calling it last discards your changes. `raise` never
weakens a rule; `override_level`
deliberately replaces it. Exact allow rules are narrow; suffix rules can expose
prefixed fields and need security review.

```rust
use qubit_redact::{
    FieldNameMatching, MaskPolicy, RedactionPolicy, Redactor, Sensitivity,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = RedactionPolicy::builder()
        .matching(FieldNameMatching::ExactOrTokenSuffix)
        .raise("license_key", Sensitivity::High)
        .allow_exact("public_token")
        .mask(Sensitivity::High, MaskPolicy::fixed("[hidden]"))
        .build()?;
    let redactor = Redactor::new(policy);

    assert_eq!(redactor.redact("LICENSE_KEY", "abc").as_str(), "[hidden]");
    assert_eq!(redactor.redact("public_token", "visible").as_str(), "visible");
    Ok(())
}
```

Use `RedactionPolicy::set_global_default` only during application startup. It
succeeds once per process; prefer explicit policy snapshots when tests or
security boundaries need isolation.

## 2. Redact scalar values and maps with `Redactor`

`redact(field, value)` is the basic operation. `redact_map` returns a copy of
the same collection type; `redact_map_in_place` updates sensitive values in an
existing map. Text-keyed `HashMap`, `BTreeMap`, and `indexmap::IndexMap` are
supported.

```rust
use std::collections::HashMap;
use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = RedactionPolicy::builder()
        .raise("password", Sensitivity::Secret)
        .build()?;
    let source = HashMap::from([
        ("password".to_owned(), "raw-password".to_owned()),
        ("display_name".to_owned(), "Ada".to_owned()),
    ]);

    let copy = Redactor::new(policy).redact_map(&source);
    assert_eq!(copy["password"], "<redacted>");
    assert_eq!(copy["display_name"], "Ada");
    assert_eq!(source["password"], "raw-password");
    Ok(())
}
```

Do not apply generic string-map redaction to heterogeneous domain objects such
as `serde_json::Map<String, serde_json::Value>`. Define an explicit domain
boundary for their replacement semantics.

## 3. Make redacted text safe for logs

Redaction and safe log rendering are distinct guarantees. A value may be
allowed by field policy but contain newlines or Unicode controls that alter log
structure. `escape_for_log()` returns displayable `LogSafeText`.
`LogOutputLimit` bounds final output and appends `<truncated>` without splitting
UTF-8 or generated escapes.

```rust
use qubit_redact::{LogOutputLimit, Redactor};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let safe = Redactor::default()
        .redact("message", "first line\nsecond line")
        .escape_for_log();
    assert_eq!(safe.to_string(), "first line\\nsecond line");

    let limit = LogOutputLimit::new(16)?;
    let bounded = safe.with_output_limit(limit).to_string();
    assert!(bounded.len() <= limit.max_bytes());
    Ok(())
}
```

Use `redacted_debug(value)` in a custom `Debug` implementation when a captured
value must always render as `<redacted>` and must never call its own `Debug`.

## 4. Redact domain objects with `Redact` and `RedactMut`

Add `qubit-redact-derive` to define redaction at field boundaries. `level` masks
a field, `nested` recurses, `map` classifies map values by key, and `skip` omits
a field from redacted representations.

```toml
[dependencies]
qubit-redact = "0.3"
qubit-redact-derive = "0.3"
```

```rust
use qubit_redact::{Redact as _, RedactMut as _};
use qubit_redact_derive::{Redact, RedactMut};

#[derive(Clone, Redact, RedactMut)]
struct Credentials {
    user: String,
    #[redact(level = "secret")]
    password: String,
    #[redact(skip)]
    internal_note: String,
}

fn main() {
    let credentials = Credentials {
        user: "ada".to_owned(),
        password: "raw-password".to_owned(),
        internal_note: "not logged".to_owned(),
    };
    assert!(!format!("{:?}", credentials.redacted()).contains("raw-password"));

    let mut mutable = credentials.clone();
    mutable.redact_in_place();
    assert_eq!(mutable.password, "<redacted>");
    assert_eq!(mutable.internal_note, "not logged");
}
```

`RedactMut` performs logical replacement only. It does not erase released
allocations, aliases, copies, or borrowed backing storage; use a dedicated
zeroization strategy when memory erasure is required.

### Serialize a redacted view with Serde

Serialization is opt-in: enable the `serde` feature, declare `serde` directly,
and add `#[redact(serde)]`. `Redacted` does not implement `Deserialize`.

```toml
[dependencies]
qubit-redact = { version = "0.3", features = ["serde"] }
qubit-redact-derive = "0.3"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

```rust
use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

#[derive(Redact)]
#[redact(serde)]
struct LoginEvent {
    account: String,
    #[redact(level = "secret")]
    token: String,
    #[redact(skip)]
    internal_note: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let event = LoginEvent {
        account: "ada".to_owned(),
        token: "raw-token".to_owned(),
        internal_note: "operator-only".to_owned(),
    };
    let json = serde_json::to_string(&event.redacted())?;
    assert!(!json.contains("raw-token"));
    assert!(!json.contains("operator-only"));
    Ok(())
}
```

## 5. Redact command arguments with `ArgvRedactor`

`redact_items` trusts sensitivity supplied by `ArgvItem`.
`redact_heuristically` also recognizes `--password value`,
`--password=value`, `-password value`, `NAME=value`, and JVM-style
`-Dpassword=value`. It does not infer compact `-pSECRET` options or shell
payloads; mark those values explicitly.

```rust
use std::ffi::OsStr;
use qubit_redact::{ArgvRedactor, Sensitivity, argv::ArgvItem};

fn main() {
    let items = [
        ArgvItem::plain(OsStr::new("client")),
        ArgvItem::plain(OsStr::new("--password")),
        ArgvItem::plain(OsStr::new("raw-password")),
        ArgvItem::sensitive(OsStr::new("raw-api-key"), Sensitivity::Secret),
    ];
    let output = ArgvRedactor::default().redact_heuristically(items).to_string();
    assert!(!output.contains("raw-password"));
    assert!(!output.contains("raw-api-key"));
}
```

`RedactedArgv` is safe to display. Input and output are bounded by the policy's
`DiagnosticBudget`.

## 6. Redact environment variables with `EnvRedactor`

`EnvRedactor` classifies a value from its variable name and returns a log-safe
`NAME=VALUE` pair. `redact_os_pair` accepts `OsStr`; non-UTF-8 input fails
closed to an opaque mask.

```rust
use qubit_redact::EnvRedactor;

fn main() {
    let redactor = EnvRedactor::default();
    let password = redactor.redact_pair("PASSWORD", "raw-password");
    let assignment = redactor.redact_assignment("API_TOKEN=raw-token");

    assert_eq!(password.to_string(), "PASSWORD=<redacted>");
    assert!(!assignment.to_string().contains("raw-token"));
}
```

Use `redact_os_pairs` for a list of process variables; it shares the input
budget and stops with a truncation marker instead of reading excess input.

## 7. Redact HTTP diagnostics with `HttpRedactor`

The optional `http` feature provides an immutable `HttpRedactionPolicy` for
headers, query/form fields, and structured bodies. Its builder starts without
field rules, as does `HttpRedactionPolicyBuilder::new()` and `Default::default()`.
Use `HttpRedactionPolicy::builder_from_default()` when extending the
conservative HTTP snapshot. `.load_default()` replaces all prior header, query,
body, behavior, and budget settings.
`HttpRedactionPolicy::default()` and `HttpRedactor::default()` continue to use
that conservative snapshot.

`HttpRedactor` applies that snapshot. `BodyCapture` supplies borrowed bytes and
truthful completeness metadata (`complete`, `prefix`, or a truncated capture),
so the library never reads a network stream. `BodyBudget` limits inspected and
rendered body bytes; `DiagnosticBudget` separately limits URLs, forms, headers,
and URL-bearing text. `BodyRedaction` is the bounded log-safe result;
`BodyRedactionStatus` tells whether it was structured, passed through,
fail-closed, binary, or empty, and `BodyRedactionReason` explains a fail-closed
outcome. No result exposes a raw-body escape hatch.

```toml
[dependencies]
qubit-redact = { version = "0.3", features = ["http"] }
http = "1.4"
```

```rust
use http::{HeaderMap, HeaderValue};
use qubit_redact::Sensitivity;
use qubit_redact::http::{BodyCapture, HttpRedactionPolicy, HttpRedactor};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = HttpRedactionPolicy::builder_from_default()
        .raise_body("password", Sensitivity::Secret)
        .raise_query("api_key", Sensitivity::Secret)
        .build()?;
    let redactor = HttpRedactor::new(policy);

    let url = redactor.redact_url_str(
        "https://api.example.test/login?api_key=raw-key&mode=debug",
    );
    assert!(!url.to_string().contains("raw-key"));

    let mut headers = HeaderMap::new();
    headers.insert("authorization", HeaderValue::from_static("Bearer raw-token"));
    assert!(!redactor.redact_headers(&headers).to_string().contains("raw-token"));

    let content_type = HeaderValue::from_static("application/json");
    let body = redactor.redact_body(
        BodyCapture::complete(br#"{"password":"raw-password","mode":"debug"}"#),
        Some(&content_type),
    );
    assert!(!body.to_string().contains("raw-password"));
    Ok(())
}
```

`HttpRedactionPolicyBuilder` offers `raise_header`, `raise_query`, and
`raise_body` for context-specific rules. Invalid or truncated structured input
fails closed.

## Choosing a tool

| Diagnostic input | Primary tool | Safe result |
| --- | --- | --- |
| Named scalar or text-keyed map | `Redactor` | `RedactedText`, then `LogSafeText` for logs |
| Rust struct or enum | `Redact` derive | `Redacted<T>` view |
| Value requiring logical replacement | `RedactMut` derive | Mutated value |
| Command arguments | `ArgvRedactor` | `RedactedArgv` |
| Environment pairs | `EnvRedactor` | `RedactedEnvPair` or `LogSafeText` |
| URL, form, headers, captured body | `HttpRedactor` | Log-safe HTTP result types |

## Security boundaries and verification

- Unknown field names pass through. Add rules for every controlled field name;
  this library is not a general secret detector.
- Allow rules deliberately reveal data and take precedence. Prefer exact rules.
- Never format `RedactedText` directly; call `escape_for_log()` first.
- Do not use `RedactMut` as a memory-erasure mechanism.
- Enable `TextBodyPolicy::PassThrough`, `UnkeyedJsonValuePolicy::PassThrough`,
  or `UrlPathPolicy::Preserve` only after accepting their disclosure risk.

Run the full feature set before publishing changed behavior or examples:

```bash
cargo test --all-features
./ci-check.sh
```
