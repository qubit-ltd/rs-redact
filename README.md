# Qubit Redact

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact.svg?color=blue)](https://crates.io/crates/qubit-redact)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![中文文档](https://img.shields.io/badge/文档-中文版-blue.svg)](README.zh_CN.md)

Policy-driven redaction for Rust diagnostics, structured fields, maps, process
arguments, environment variables, and optional HTTP data.

## Design

Qubit Redact separates four concerns:

- `RedactionPolicy` is an immutable snapshot of field rules, allow rules,
  matching behavior, and masks.
- `Redactor` applies one policy to scalar field values and string maps.
- `ArgvRedactor` and `EnvRedactor` produce typed, log-safe process diagnostics.
- The optional `http` module handles URLs, forms, headers, and bounded bodies.

Unknown fields pass through unchanged. Redaction is therefore based on known
structure and configured names, not general secret detection. The default
policy provides conservative presets, while the builder supports application
rules and explicit allow decisions.

## Cargo Features

The default feature set is empty and the core crate has no external runtime
dependencies.

| Feature | Capability | Optional dependencies |
| --- | --- | --- |
| `serde` | Serialization of explicitly opted-in redacted views | `serde` |
| `http` | URL, form, header, and bounded body redaction | `form_urlencoded`, `http`, `serde_json`, `url` |

```toml
[dependencies]
# Enable HTTP support only where it is needed:
# cargo add qubit-redact --features http
# cargo add http@1.4
qubit-redact = { version = "0.3", features = ["http"] }
qubit-redact-derive = "0.3"
http = "1.4"
```

Use `qubit-redact = "0.3"` instead when only the dependency-free core is
needed.

## Scalar Values and Maps

```rust
use std::collections::HashMap;

use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = RedactionPolicy::builder()
        .raise("tenant_secret", Sensitivity::Secret)
        .build()?;
    let source = HashMap::from([
        ("tenant_secret".to_owned(), "raw".to_owned()),
        ("display_name".to_owned(), "Alice".to_owned()),
    ]);
    let redacted = Redactor::new(policy).redact_map(&source);
    assert_eq!(redacted["tenant_secret"], "<redacted>");
    assert_eq!(source["tenant_secret"], "raw");
    Ok(())
}
```

`redact_map_in_place` provides the corresponding mutating operation. Both map
methods classify each value from its key and preserve safe values.

## Policy Configuration

```rust
use qubit_redact::{
    FieldNameMatching, MaskPolicy, RedactionPolicy, Redactor, Sensitivity,
};

fn main() {
    let policy = RedactionPolicy::builder()
        .matching(FieldNameMatching::ExactOrTokenSuffix)
        .raise("license_key", Sensitivity::High)
        .allow_exact("public_token")
        .mask(Sensitivity::High, MaskPolicy::fixed("[hidden]"))
        .build()
        .expect("the policy is valid");

    RedactionPolicy::set_global_default(policy.clone())
        .expect("the application installs its default only once");
    let inherited = RedactionPolicy::builder()
        .build()
        .expect("the default snapshot remains valid");
    assert_eq!(inherited.sensitivity_for("license_key"), Some(Sensitivity::High));

    let redactor = Redactor::new(policy);
    assert_eq!(redactor.redact("LICENSE_KEY", "abcdef").as_str(), "[hidden]");
}
```

`raise` never weakens an existing rule. Use `override_level` only when an
intentional replacement, including a downgrade, is required. Exact allow rules
affect only the complete canonical field. Suffix allow rules can also allow
prefixed names such as `request_public_token`; they are broader disclosure
decisions and should be used only after reviewing that risk.

`RedactionPolicy::default()` reads the current process-wide default snapshot.
`RedactionPolicy::set_global_default(policy)` can successfully install a custom
default only once; a later call returns `GlobalDefaultAlreadySet` and never
replaces it. `RedactionPolicy::builder()` starts from the default at the time it
is called. Previously created policies, builders, and redactors remain
unchanged.

## Domain Objects

Add the companion `qubit-redact-derive` crate to describe redaction at the
field boundary. Unmarked fields remain ordinary values; recursion and Map key
classification are always explicit.

```rust
use std::collections::HashMap;

use qubit_redact::{Redact as _, RedactionPolicy, Sensitivity};
use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Account {
    id: u64,
    #[redact(level = "secret")]
    password: String,
    #[redact(map)]
    metadata: HashMap<String, String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = RedactionPolicy::empty_builder()
        .raise("api_key", Sensitivity::Secret)
        .build()?;
    let account = Account {
        id: 1,
        password: "raw-password".to_owned(),
        metadata: HashMap::from([
            ("api_key".to_owned(), "raw-key".to_owned()),
        ]),
    };
    let output = format!("{:?}", account.redacted_with(&policy));
    assert!(!output.contains("raw-password"));
    assert!(!output.contains("raw-key"));
    Ok(())
}
```

Use `#[redact(nested)]` for a field whose type implements `Redact`; without
that attribute even a derived field type is not traversed. `#[redact(skip)]`
omits a field from redacted Debug, Display, and serde output. It does not
remove or modify the field on the original object, and `RedactMut` leaves it
unchanged.

`RedactMut` is a separate, explicit destructive contract. Its
`redact_in_place`, `into_redacted`, and clone-based `to_redacted` operations
support the same `level`, `nested`, and `map` field modes. `to_redacted`
briefly creates a second copy of the original sensitive data; prefer
`redact_in_place` or `into_redacted` for highly sensitive values.

Enable `serde` and use the companion derive crate, then add `#[redact(serde)]`
to opt a named struct into serialization of its redacted view. The consuming
crate must declare `serde` directly (a renamed dependency is supported); the
runtime crate does not re-export it. `Redacted` does not implement
`Deserialize`.

```rust
use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

#[derive(Redact)]
#[redact(debug, display, serde)]
struct Credentials {
    #[redact(level = "secret")]
    token: String,
    #[redact(skip)]
    internal_note: String,
}

let value = Credentials {
    token: "raw-token".to_owned(),
    internal_note: "not serialized".to_owned(),
};
let json = serde_json::to_string(&value.redacted()).unwrap();
assert!(!json.contains("raw-token"));
assert!(!json.contains("internal_note"));
assert!(!format!("{value:?}").contains("raw-token"));
assert!(!format!("{value}").contains("raw-token"));
```

`#[redact(debug)]` and `#[redact(display)]` opt the original type into safe
formatting through the process-wide default policy. They do not infer
sensitivity from unmarked field names. Do not combine either option with an
existing implementation of the same trait, including `#[derive(Debug)]` with
`#[redact(debug)]`, because Rust correctly reports conflicting implementations.

`redacted()` snapshots the process-wide default policy. `redacted_with`
snapshots an explicit policy, and every nested or Map field uses that same
snapshot. Field-specific Map policies are intentionally unsupported in the
first version; use a domain newtype with `nested` when a field needs a
different policy boundary. Derives currently support named structs only.

## Process Diagnostics

`ArgvRedactor::redact_items` trusts explicit sensitivity metadata and performs
no command-line inference. `redact_heuristically` additionally recognizes
common option and assignment forms. Shell payloads are never parsed as scripts.

`EnvRedactor` redacts UTF-8 pairs and fails closed when either operating-system
component is not valid UTF-8. Its result safely renders as `NAME=VALUE`.
Use `redacted_debug` in custom `Debug` implementations when a captured value
must render only as `<redacted>`; the wrapper never calls the value's own
`Debug` implementation.

```rust
use std::ffi::OsStr;

use qubit_redact::{ArgvRedactor, EnvRedactor, argv::ArgvItem};

fn main() {
    let items = [
        ArgvItem::plain(OsStr::new("client")),
        ArgvItem::plain(OsStr::new("--password")),
        ArgvItem::plain(OsStr::new("secret")),
    ];
    let output = ArgvRedactor::default().redact_heuristically(items);
    assert!(!output.to_string().contains("secret"));

    let environment = EnvRedactor::default().redact_pair("PASSWORD", "secret");
    assert_eq!(environment.to_string(), "PASSWORD=<redacted>");

    let captured_bytes = b"secret output";
    assert_eq!(
        format!("{:?}", qubit_redact::redacted_debug(captured_bytes)),
        "<redacted>",
    );

    let log_safe = qubit_redact::Redactor::default()
        .redact("message", "line one\nline two")
        .escape_for_log();
    assert_eq!(log_safe.to_string(), "line one\\nline two");
}
```

`RedactedText` deliberately does not implement `Display`: redaction and log
escaping are different guarantees. Always call `escape_for_log()` before
rendering a scalar result into a plain-text log sink. The argv and environment
result types already cross that boundary and implement safe `Display`.

## HTTP Redaction

Enable `http` with `cargo add qubit-redact --features http`, and add the direct
`http` dependency used by the example with `cargo add http@1.4` (or use the
equivalent Cargo.toml entries above). `HttpRedactor` owns an immutable
`HttpRedactionPolicy` and provides URL, URL-encoded form, header, and body
operations. `BodyCapture` distinguishes complete input from checked truncated
input, while `BodyBudget` bounds both parsing input and rendered output.

Malformed or truncated structured bodies fail closed. Opaque text, unkeyed JSON
scalars, file parts, unnamed multipart parts, and URL paths use conservative
defaults. The HTTP result types expose only log-safe text; they do not expose a
raw-body escape hatch.

```rust
use http::HeaderValue;
use qubit_redact::http::{BodyCapture, BodyRedaction, HttpRedactor};

fn main() {
    let body = br#"{"password":"secret","mode":"debug"}"#;
    let content_type = HeaderValue::from_static("application/json");
    let result: BodyRedaction = HttpRedactor::default()
        .redact_body(BodyCapture::complete(body), Some(&content_type));
    let display_text = format!("{result}");
    assert!(!display_text.contains("secret"));
}
```

HTTP redaction accepts only a caller-provided, bounded capture; it does not read
or buffer a network body. `BodyRedaction`'s `Display` implementation is the safe
logging boundary and preserves the configured output budget.

`TextBodyPolicy::PassThrough`, `UnkeyedJsonValuePolicy::PassThrough`, and
`UrlPathPolicy::Preserve` are explicit diagnostic opt-ins. Choose them only
after the application has accepted the corresponding disclosure risk.

## Safety Boundaries

- Field names are canonicalized and can use exact or token-suffix matching.
- Allow rules win deliberately and can expose data; review them as security
  policy.
- Redaction does not discover secrets stored under unknown field names.
- `RedactedText` distinguishes field redaction from `LogSafeText`, which also
  escapes controls and Unicode line-ordering characters.
- Treat typed display results as the logging boundary instead of rebuilding
  strings from raw inputs.

## Testing

```bash
# Run tests with the default feature set
cargo test

# Run tests with all declared features
cargo test --all-features

# Project CI checks
./ci-check.sh

# Check code coverage
./coverage.sh
```

## License

Copyright (c) 2025 - 2026. Haixing Hu. All rights reserved.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the
full license text.

## Contributing

Contributions are welcome. Please follow the Rust API guidelines, keep public
API documentation and tests current, and run `./align-ci.sh` to format code and
`./ci-check.sh` to satisfy CI requirements before submitting a pull request.

## Author

**Haixing Hu** - *Qubit Co. Ltd.*

Repository: [https://github.com/qubit-ltd/rs-redact](https://github.com/qubit-ltd/rs-redact)
