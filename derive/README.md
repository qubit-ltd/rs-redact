# qubit-redact-derive

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact-derive.svg?color=blue)](https://crates.io/crates/qubit-redact-derive)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![中文文档](https://img.shields.io/badge/文档-中文版-blue.svg)](README.zh_CN.md)

`qubit-redact-derive` generates borrowed domain redaction and `RedactScalar` capabilities.
Business developers classify fields; complex objects delegate their internal rules through `nested`.

## Installation

Prefer the runtime re-export; a separate derive dependency is unnecessary:

```toml
[dependencies]
qubit-redact = { version = "0.7", features = ["derive", "serde", "json"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

## Quick Start

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

## Field and Container Attributes

| Field attribute | Meaning / supported values |
| --- | --- |
| None | Ordinary `Debug`; with the runtime `serde` feature, the view serializes through the generated redacted projection when its fields support Serde. |
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
The source need not implement `Serialize`: view serialization and `to_json()` require only
a serializable redacted projection.
`transparent` requires exactly one field and delegates its representation; it does not declare scalar capability.
Do not derive ordinary `Debug` together with `debug`, or ordinary `Serialize` together with `serde`.

## Scalar Value Objects

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

`RedactScalar` requires exactly one scalar field and supports named/tuple structs and nested
scalar wrappers. It generates no ordinary Debug, Display, or Serialize and selects no sensitivity.
Containers are not scalar inner fields. Third-party types use `#[redact(level = "secret", display)]`.

`max_serde_payload_bytes` bounds logical scalar payloads in structured Serde;
`max_output_bytes` bounds final text or `to_json()` JSON retained by the library.
Both default to 16 KiB and are independent. When serializing a view or derived source directly,
the caller's serializer/writer controls final encoded length. See the guide's budget matrix.

## Learn More

See the [English user guide](../doc/user_guide.md), [Chinese user guide](../doc/user_guide.zh_CN.md),
and [runtime README](../README.md) for budgets, Serde compatibility, snapshots, and disabled policy.

## Testing

Run these commands from the repository root (the parent of `derive/`).

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
