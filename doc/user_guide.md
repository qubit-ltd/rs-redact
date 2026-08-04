# Qubit Redact User Guide

[README](../README.md) · [中文用户手册](user_guide.zh_CN.md) · [Runtime API](https://docs.rs/qubit-redact) · [Derive README](https://github.com/qubit-ltd/rs-redact-derive/blob/main/README.md) · [Derive User Guide](https://github.com/qubit-ltd/rs-redact-derive/blob/main/doc/user_guide.md)

Qubit Redact is a policy-driven Rust library for preventing sensitive values from
leaking through diagnostics: structured fields and maps, Rust domain objects,
process arguments, environment variables, and optional HTTP data.

## Contents

- [Installation and example requirements](#installation-and-example-requirements)
- [Configure a policy](#1-configure-redactionpolicy)
- [Scalar values, maps, and log text](#2-redact-scalar-values-and-maps-with-redactor)
- [Domain objects](#4-redact-domain-objects-with-redact-and-redactmut)
- [Process diagnostics](#5-redact-command-arguments-with-argvredactor)
- [HTTP diagnostics](#7-redact-http-diagnostics-with-httpredactor)
- [URI diagnostics](#8-redact-uri-diagnostics-with-uriredactor)
- [Security checklist and troubleshooting](#security-boundaries-and-verification)

## What it solves

Secrets commonly leak through error logs, debug dumps, and serialized
diagnostics, not through the authentication code that received them. Replacing
strings at individual log calls is easy to omit and hard to review. Qubit Redact
centralizes that decision in an immutable `RedactionPolicy`.

This complete program keeps the original secret unchanged and masks the
diagnostic value.

```toml
[dependencies]
qubit-redact = "0.4"
```

```rust
use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = RedactionPolicy::builder();
    builder.fields().raise("user_id", Sensitivity::Low)?;
    builder.fields().raise("phone_number", Sensitivity::Medium)?;
    builder.fields().raise("credit_card", Sensitivity::High)?;
    builder.fields().raise("api_key", Sensitivity::Secret)?;
    let policy = builder.build()?;
    let redactor = Redactor::new(policy);
    let user_id = "alpine42";
    let phone_number = "13800138000";
    let credit_card = "4111111111111111";
    let api_key = "sk_live_123";
    let display_name = "Alice\nAdmin";

    assert_eq!(redactor.redact_field("user_id", user_id).as_str(), "al****42");
    assert_eq!(redactor.redact_field("phone_number", phone_number).as_str(), "*******0");
    assert_eq!(redactor.redact_field("credit_card", credit_card).as_str(), "****");
    assert_eq!(redactor.redact_field("api_key", api_key).as_str(), "<redacted>");
    assert_eq!(redactor.redact_field("display_name", display_name).as_str(), display_name);
    assert_eq!(api_key, "sk_live_123");
    assert_eq!(
        redactor
            .redact_field("display_name", display_name)
            .escape_for_log()
            .to_string(),
        "Alice\\nAdmin",
    );
    Ok(())
}
```

## Choosing a tool

| Diagnostic input | Primary tool | Result and logging boundary |
| --- | --- | --- |
| Named scalar value | `Redactor::redact_field` | `RedactedText`, then `LogSafeText` for plain-text logs |
| Text-keyed map | `Redactor::redact_map` or `redact_map_in_place` | A copied or mutated map; choose the final logging format explicitly |
| Rust struct or enum | `Redact` derive | `Redacted<T>` view |
| Value requiring logical replacement | `RedactMut` derive | Mutated value; not memory erasure |
| Command arguments | `ArgvRedactor` | `RedactedArgv` |
| Environment pairs | `EnvRedactor` | `RedactedEnvPair` or `LogSafeText` |
| URL, form, headers, captured body | `HttpRedactor` | Log-safe HTTP result types |

## Installation and example requirements

The package is `qubit-redact` and Rust imports it as `qubit_redact`. The default
feature set has no runtime dependencies. Add the derive crate for domain
objects, enable `serde` for redacted serialization, and enable `http` for HTTP
diagnostics. Each Rust block is a complete `main.rs`; use the dependency block
shown by its section and run `cargo run`.

```toml
[dependencies]
qubit-redact = { version = "0.4", features = ["serde", "http"] }
qubit-redact-derive = "0.4"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
http = "1.5"
```

## Core concepts

A `RedactionPolicy` is one immutable snapshot of base field rules, HTTP/URI
context overrides, an optional minimum `RedactionFloor`, matching behavior,
one masking table, and static limits. With the `json` feature it also carries a
`JsonDepthBudget`. `classify_field()` explains the application layer only:
**Sensitive**, **Allowed** by an explicit exception, or **Unknown**. Final
field safety decisions come from `sensitivity_for()` and the redaction APIs,
which combine the application layer with the floor. `UnknownFieldPolicy`
defaults to `PassThrough`; set `Redact(Sensitivity::Secret)` when an
unclassified field must be masked without changing the observable
`classify_field()` result. `RedactionPolicy::strict()` provides this boundary
preset while leaving the default policy unchanged. `Redactor` owns one
snapshot and applies it consistently.

`RedactedText` means field-sensitive redaction occurred. It intentionally does
not implement `Display`: call `escape_for_log()` before a plain-text log
boundary to obtain `LogSafeText`.

Redacted domain and map views use the policy diagnostic output budget for
`Debug` by default. Call `with_policy_output_limit()` when both `Debug` and
`Display` output must be explicitly bounded by that same budget. Derived nested
values, maps, JSON text, and adapter sessions share one non-cloneable
`RedactionSession`, so a nested value cannot reset the parent's budget.

`InputOutputLimit` is the immutable limit stored in a policy. One runtime
`RedactionSession` tracks an operation or diagnostic event. Callers may charge
custom inspected input through `consume_input()`; redaction adapters commit
their own output atomically, including any fallback marker, so eager fragments
cannot exceed the cumulative output allowance.

| API | Starting state | Use it when |
| --- | --- | --- |
| `RedactionPolicy::default()` | Installed process-wide snapshot, or fixed standard policy | You accept the application's current default. |
| `RedactionPolicy::builder()` | Empty application rules plus the standard floor | You need application rules defined at this call site while retaining the floor. |
| `RedactionPolicy::default().to_builder()` | Copy of the current default snapshot | You want to extend the standard default. |
| `RedactionPolicy::install_global()` | Installs once per process | Application startup owns the default policy snapshot. |

Use `include_preset(SensitiveFieldPreset::...)` to add the built-in credential,
credential-container, auth-token, HTTP, or session field groups to an explicit
policy. Use `classify_field()` when a policy test or diagnostic must explain a
`Sensitive`, `Allowed`, or `Unknown` decision.

## 1. Configure `RedactionPolicy`

`RedactionPolicy::builder()` starts with no application sensitive or
allow rules and uses the standard floor. `RedactionPolicy::default()` reads
the installed process-wide snapshot, or the fixed standard policy before one
is installed. Use
`RedactionPolicy::default().to_builder()` to extend that snapshot; use
`disable_floor()` only when the caller intentionally accepts removal of all
minimum protection. An application allow rule never bypasses an enabled floor.
Builders do not load global state implicitly. `raise` never
weakens a rule; `override_level`
deliberately replaces it. Exact allow rules are narrow; suffix rules can expose
prefixed fields and need security review.

```rust
use qubit_redact::{
    FieldNameMatching, MaskPolicy, RedactionPolicy, Redactor, Sensitivity,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = RedactionPolicy::builder();
    builder
        .fields()
        .matching(FieldNameMatching::ExactOrTokenSuffix)
        .raise("tenant_reference", Sensitivity::High)?
        .raise("tenant_visible", Sensitivity::High)?
        .allow_exact("tenant_visible")?
        .mask(Sensitivity::High, MaskPolicy::fixed("[hidden]"))?;
    let policy = builder.build()?;
    let redactor = Redactor::new(policy);

    assert_eq!(redactor.redact_field("TENANT_REFERENCE", "abc").as_str(), "[hidden]");
    assert_eq!(redactor.redact_field("tenant_visible", "visible").as_str(), "visible");
    Ok(())
}
```

Install the global policy only during application startup:

```rust
use qubit_redact::{RedactionPolicy, Sensitivity};

let mut builder = RedactionPolicy::builder();
builder.fields().raise("api_key", Sensitivity::Secret)?;
let policy = builder.build()?;
RedactionPolicy::install_global(policy)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Installation succeeds once per process. If `global()` or `default()` is read
first, the standard policy is frozen and a later installation returns
`InstallGlobalPolicyError`. Prefer explicit policy snapshots when tests or
security boundaries need isolation.

Field names are canonicalized. With `FieldNameMatching::ExactOrTokenSuffix`, a
rule for `api_key` can match `request_api_key`; exact matching has the narrowest
scope.

`raise(field, level)` is monotonic in two ways. Repeated configuration of the
same canonical key retains its highest level, and final resolution takes the
highest level among all differently named rules that match the input. For
example, `token = Secret` and `access_token = Medium` both match
`OPENAI_ACCESS_TOKEN`, so its final sensitivity is `Secret`.
`override_level("access_token", Medium)` replaces only that canonical rule; it
does not bypass the overlapping `token = Secret` rule. Use it to correct one
rule's configured level, not to lower the aggregate protection of overlapping
rules.

Allow resolution is separate from sensitive-level aggregation. Exact allow
rules affect one canonical field; suffix allow rules can reveal prefixed fields
and need a security review. If an allow rule does not release the field, every
matching sensitive rule contributes to the maximum; an enabled floor remains
independently effective.

Use `Redactor::redact_at(level, value)` at a boundary that already knows a value
is sensitive independently of its field name. It applies that mask directly, so
an allow rule cannot expose the value.

## 2. Redact scalar values and maps with `Redactor`

`redact_field(field, value)` is the basic operation and returns a
`FieldRedaction` result that distinguishes masked, allowed, and unknown values.
`redact_map` returns a copy of
the same collection type; `redact_map_in_place` updates sensitive values in an
existing map. Text-keyed `HashMap`, `BTreeMap`, and `indexmap::IndexMap` are
supported.

It classifies only `field`; it does not scan `value`. For example,
`redact_field("error", "request failed: password=raw-secret")` passes the whole
value through when `error` has no sensitive rule—the library does not discover
the embedded `password=` syntax. Redact parsed data as structured fields. For
an untrusted complete error string, expose a fixed safe summary and retain the
original error through `Error::source()`, or use
`redact_at(Sensitivity::Secret, text)` when the entire opaque value must be
treated as sensitive.

```rust
use std::collections::HashMap;
use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = RedactionPolicy::builder()
        .raise("user_id", Sensitivity::Low)?
        .raise("phone_number", Sensitivity::Medium)?
        .raise("credit_card", Sensitivity::High)?
        .raise("api_key", Sensitivity::Secret)?
        .build()?;
    let source = HashMap::from([
        ("user_id".to_owned(), "alpine42".to_owned()),
        ("phone_number".to_owned(), "13800138000".to_owned()),
        ("credit_card".to_owned(), "4111111111111111".to_owned()),
        ("api_key".to_owned(), "sk_live_123".to_owned()),
        ("display_name".to_owned(), "Alice".to_owned()),
    ]);

    let copy = Redactor::new(policy).redact_map(&source);
    assert_eq!(copy["user_id"], "al****42");
    assert_eq!(copy["phone_number"], "*******0");
    assert_eq!(copy["credit_card"], "****");
    assert_eq!(copy["api_key"], "<redacted>");
    assert_eq!(copy["display_name"], "Alice");
    assert_eq!(source["api_key"], "sk_live_123");
    Ok(())
}
```

Do not apply generic string-map redaction to heterogeneous domain objects such
as `serde_json::Map<String, serde_json::Value>`. Define an explicit domain
boundary for their replacement semantics.

`redact_map` returns the same collection type, while `redact_map_in_place`
updates that collection. Neither operation turns a map into `LogSafeText`;
choose an appropriate final formatter at the logging boundary.

With the `json` feature, `RedactedJson`, `RedactedJsonText`, and
`redact_json_text_in_place` all use the immutable policy's `JsonDepthBudget`.
The root has depth zero; when another object or array would reach the configured
maximum, that complete subtree is replaced with the policy's opaque Secret mask
without visiting its descendants. The default maximum depth is 128. Configure a
smaller positive limit with
`RedactionPolicyBuilder::limits().json_depth(...)` when an input boundary
requires it.

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
        .redact_field("message", "first line\nsecond line")
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

`qubit-redact-derive` provides procedural macros that apply the runtime policy
to Rust structs and enums. `Redact` creates a borrowed view for diagnostics;
`RedactMut` explicitly replaces logical values when an owned value is required.
At field boundaries, `level` masks a field, `plain` documents intentional
visibility, `nested` recurses, `map` classifies map values by key, and `skip`
omits a field from redacted representations. Add
`#[redact(require_explicit)]` when every field must select one of these modes;
the default behavior remains unchanged. See the [derive README](https://github.com/qubit-ltd/rs-redact-derive/blob/main/README.md)
and [derive User Guide](https://github.com/qubit-ltd/rs-redact-derive/blob/main/doc/user_guide.md) for the complete macro
reference and examples.

```toml
[dependencies]
qubit-redact = "0.4"
qubit-redact-derive = "0.4"
```

```ignore
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

Plain fields are never traversed implicitly. Derives support named, tuple, and
unit structs plus enums with those variant shapes.

### Serialize a redacted view with Serde

Serialization is opt-in: enable the `serde` feature, declare `serde` directly,
and add `#[redact(serde)]`. `Redacted` does not implement `Deserialize`.

For a `String` that stores JSON, enable the `json` feature and use
`#[redact(json)]`. It recursively applies the policy to JSON object keys,
renders a redacted view for `Redact`, rewrites compact redacted JSON for
`RedactMut`, and fails closed to an opaque mask when parsing fails. Serde keeps
the field as a JSON string rather than embedding the parsed object.

`#[redact(debug)]` and `#[redact(display)]` opt the original type into safe
formatting through the process-wide default policy. Do not combine either with
an existing implementation of the same trait.

```toml
[dependencies]
qubit-redact = { version = "0.4", features = ["serde"] }
qubit-redact-derive = "0.4"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

```ignore
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
`InputOutputLimit`.

When rendering an argument collection, the collection framing is retained even
if the shared input budget is exhausted before the first item can be read; in
that case the safe result may be `['<truncated>']`.

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

The optional `http` feature provides an immutable root `RedactionPolicy` for
headers, query/form fields, and structured bodies. Its `http()` view stores
only context differences; base-field rules, masking, and limits remain on the
same policy. `RedactionPolicy::builder()` starts with no application field
rules and the standard floor. Application allow rules cannot bypass an
enabled floor. Use `RedactionPolicy::default().to_builder()` when extending
the standard snapshot; the builder does not load global state implicitly.
`RedactionPolicy::default()` and `HttpRedactor::default()` preserve URL
paths for diagnostic usefulness; use `RedactionPolicy::strict()` or set
`UrlPathPolicy::Redact` when URL paths may contain sensitive identifiers.

`HttpRedactor` applies that snapshot. `BodyCapture` supplies borrowed bytes and
truthful completeness metadata (`complete`, `prefix`, or a truncated capture),
so the library never reads a network stream. `BodyBudget` limits inspected and
rendered body bytes; `InputOutputLimit` separately limits URLs, forms, headers,
and URL-bearing text; `JsonDepthBudget` bounds JSON and NDJSON recursion.
`BodyRedaction` is the bounded log-safe result;
`BodyRedactionStatus` tells whether it was structured, passed through,
fail-closed, binary, or empty, and `BodyRedactionReason` explains a fail-closed
outcome. No result exposes a raw-body escape hatch.

| Input | Default safety behavior | Configure with |
| --- | --- | --- |
| URL query, username, password, fragment | Redacts configured fields and sensitive URL components | `builder.http().query().raise(...)`, `builder.uri()`, `UrlPathPolicy` |
| Form and headers | Redacts configured fields; output is bounded | `builder.http().header()` and `builder.http().query()` |
| JSON, NDJSON, form body, multipart | Parses complete input and fails closed when unsafe, over-depth, or truncated | `builder.http().body()`, `builder.limits()`, `JsonDepthBudget` |
| Opaque text, unkeyed JSON | Conservative by default | Explicit `PassThrough` only after risk review |
| URL path | Preserved by the standard policy; redacted by strict policy | `UrlPathPolicy::Redact` or `RedactionPolicy::strict()` |
| Non-UTF-8 body | Returns a binary summary, never raw bytes | `BodyRedactionStatus::Binary` |

```toml
[dependencies]
qubit-redact = { version = "0.4", features = ["http"] }
http = "1.5"
```

```rust
use http::{HeaderMap, HeaderValue};
use qubit_redact::{RedactionPolicy, Sensitivity};
use qubit_redact::http::{BodyCapture, HttpRedactor};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = RedactionPolicy::default().to_builder();
    builder
        .http()
        .body()
        .raise("password", Sensitivity::Secret)?;
    builder
        .http()
        .query()
        .raise("api_key", Sensitivity::Secret)?;
    let policy = builder.build()?;
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
    assert!(matches!(body.status(), qubit_redact::http::BodyRedactionStatus::Structured));
    assert!(!body.to_string().contains("raw-password"));
    Ok(())
}
```

One `RedactionPolicyBuilder` offers context-aware rule, floor, sensitivity,
and allow-list methods through `http().header()`, `http().query()`, and
`http().body()`. Configure the shared static limits through `limits()`.
Invalid or truncated structured input fails closed.

For operational diagnostics, inspect `BodyRedaction::status()`,
`is_truncated()`, `captured_len()`, and `omitted_len()`. A
`BodyRedactionStatus::Redacted(reason)` value reports why a structured or
visible representation was unsafe.

## 8. Redact URI diagnostics with `UriRedactor`

The optional `uri` feature adds a parser-backed URI facade without enabling
the HTTP feature:

```toml
qubit-redact = { version = "0.4", features = ["uri"] }
```

`UriRedactor` preserves raw scheme, host, port, path, query order, and
percent-encoding for visible components. Userinfo is split only at the first
raw, unencoded `:`: the username uses the `username` field rule and the
password uses `password`. A username-only authority is visible under the
standard policy and can be allowed or masked by the same core policy rules.

Query keys and values are decoded strictly for policy decisions. `+` remains a
literal plus, the first `=` separates a pair, and unmasked values retain their
original raw spelling. Masked values are URI-encoded again. Paths are
preserved by default; fragments are redacted by default and both choices are
configurable through `builder.uri().path(...)` and `builder.uri().fragment(...)`.
Invalid syntax, undecodable
query UTF-8, or an input budget violation return `<invalid URI>` without
retaining source text.

`UriRedaction` exposes log-safe text, status, changed components, reasons, and
output truncation metadata. Its `Debug` and `Display` implementations render
only that safe result.

## Security boundaries and verification

- Unknown field names pass through unless `UnknownFieldPolicy::Redact(...)` is
  configured. `RedactionPolicy::strict()` is a ready-to-use boundary preset
  that masks unknown fields at `Sensitivity::Secret`; the default policy is
  unchanged. Add rules for every controlled field name; this library is not a
  general secret detector.
- Allow rules deliberately reveal data and take precedence. Prefer exact rules.
- Never format `RedactedText` directly; call `escape_for_log()` first.
- Call `with_policy_output_limit()` when a redacted domain or map view must be
  bounded by its diagnostic budget.
- Do not use `RedactMut` as a memory-erasure mechanism.
- Enable `TextBodyPolicy::PassThrough`, `UnkeyedJsonValuePolicy::PassThrough`,
  or `UrlPathPolicy::Preserve` only after accepting their disclosure risk.

| Situation | What to do |
| --- | --- |
| A controlled field remained visible | Add an explicit rule; unknown fields pass through. |
| A suffix rule exposed too much | Prefer an exact rule, or remove the suffix allow rule. |
| A policy fails to build | Inspect the returned `PolicyError`; do not replace it with a permissive fallback. |
| A global policy is already installed | Handle `InstallGlobalPolicyError`; pass an explicit policy where isolation matters. |
| A structured body is malformed or truncated | Log the safe result and inspect `BodyRedactionStatus::Redacted(reason)`. |
| A log line contains controls or Unicode line separators | Cross the scalar boundary with `escape_for_log()`. |
| Memory erasure is required | Do not rely on `RedactMut`; use a dedicated zeroization design. |

Run the full feature set before publishing changed behavior or examples:

```bash
cargo test --all-features
./ci-check.sh
```
