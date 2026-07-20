# Qubit Redact

[![Rust CI](https://github.com/qubit-ltd/rs-sanitize/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-sanitize/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-sanitize/coverage-badge.json)](https://qubit-ltd.github.io/rs-sanitize/coverage/)
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
| `http` | URL, form, header, and bounded body redaction | `form_urlencoded`, `http`, `serde_json`, `url` |

```toml
[dependencies]
qubit-redact = "0.1"

# Enable HTTP support only where it is needed.
qubit-redact-http = { package = "qubit-redact", version = "0.1", features = ["http"] }
```

## Scalar Values and Maps

```rust
use std::collections::BTreeMap;

use qubit_redact::{RedactionPolicy, Redactor};

let redactor = Redactor::new(RedactionPolicy::default());
assert_eq!(redactor.redact("password", "secret").as_ref(), "<redacted>");
assert_eq!(redactor.redact("mode", "debug").as_ref(), "debug");

let values = BTreeMap::from([
    ("password".to_owned(), "secret".to_owned()),
    ("mode".to_owned(), "debug".to_owned()),
]);
let redacted = redactor.redact_map(&values);
assert_eq!(redacted["password"], "<redacted>");
assert_eq!(redacted["mode"], "debug");
```

`redact_map_in_place` provides the corresponding mutating operation. Both map
methods classify each value from its key and preserve safe values.

## Policy Configuration

```rust
use qubit_redact::{
    FieldNameMatching, MaskPolicy, RedactionPolicy, Redactor, Sensitivity,
};

let policy = RedactionPolicy::builder()
    .matching(FieldNameMatching::ExactOrTokenSuffix)
    .raise("license_key", Sensitivity::High)
    .allow_exact("public_token")
    .mask(Sensitivity::High, MaskPolicy::fixed("[hidden]"))
    .build()
    .expect("the policy is valid");

let redactor = Redactor::new(policy);
assert_eq!(redactor.redact("LICENSE_KEY", "abcdef").as_ref(), "[hidden]");
```

`raise` never weakens an existing rule. Use `override_level` only when an
intentional replacement, including a downgrade, is required. Exact allow rules
affect only the complete field; suffix allow rules are broader disclosure
decisions and should be used sparingly.

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

use qubit_redact::{ArgvRedactor, argv::ArgvItem};

let items = [
    ArgvItem::plain(OsStr::new("client")),
    ArgvItem::plain(OsStr::new("--password")),
    ArgvItem::plain(OsStr::new("secret")),
];
let output = ArgvRedactor::default().redact_heuristically(items);
assert!(!output.to_string().contains("secret"));

let captured_bytes = b"secret output";
assert_eq!(
    format!("{:?}", qubit_redact::redacted_debug(captured_bytes)),
    "<redacted>",
);
```

## HTTP Redaction

Enable `http` to use `HttpRedactor`. It owns an immutable
`HttpRedactionPolicy` and provides URL, URL-encoded form, header, and body
operations. `BodyCapture` distinguishes complete input from checked truncated
input, while `BodyBudget` bounds both parsing input and rendered output.

Malformed or truncated structured bodies fail closed. Opaque text, unkeyed JSON
scalars, file parts, unnamed multipart parts, and URL paths use conservative
defaults. The HTTP result types expose only log-safe text; they do not expose a
raw-body escape hatch.

```rust
# #[cfg(feature = "http")]
# {
use http::HeaderValue;
use qubit_redact::http::{BodyCapture, HttpRedactor};

let body = br#"{"password":"secret","mode":"debug"}"#;
let content_type = HeaderValue::from_static("application/json");
let result = HttpRedactor::default()
    .redact_body(BodyCapture::complete(body), Some(&content_type));
assert!(!result.to_string().contains("secret"));
# }
```

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

Repository: [https://github.com/qubit-ltd/rs-sanitize](https://github.com/qubit-ltd/rs-sanitize)
