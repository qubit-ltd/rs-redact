# qubit-redact

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact.svg?color=blue)](https://crates.io/crates/qubit-redact)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![中文文档](https://img.shields.io/badge/文档-中文版-blue.svg)](README.zh_CN.md)

`qubit-redact` gives application and library authors a consistent redaction boundary for
logs, errors, and support diagnostics. A borrowed view produces redacted text or JSON without
changing the source object's ordinary serialization. Add `#[redact(serde)]` when the source
object's own Serde output must also be redacted.

## Installation

The complete example uses derive, Serde, and JSON. Scalar text operations need no features.

```toml
[dependencies]
qubit-redact = { version = "0.8", features = ["derive", "serde", "json"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

## Quick Start

With `#[redact(serde)]`, business JSON and diagnostic JSON both replace the password
with `<redacted>`. The generated Debug implementation also redacts ordinary diagnostic formatting.

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

## Choose an Entry Point

| Need | Entry point |
| --- | --- |
| Lazy formatting or serialization under a fixed policy | `redact_view(&value)` |
| Final text and completeness summary now | `redact_text(&value)` |
| Compact redacted JSON string | `to_json(&value)` |
| Redact input that is already JSON | `redact_json(text)` / `redact_json_value(&value)` |
| Share one budget across independent values | `batch()` |
| Compose one diagnostic message | `text_composer()` |

## Why This Project Exists

Configure classification, masking, format handling, and resource budgets in one place
instead of implementing them at every log site. Views retain policy snapshots and execute
on each use; finalized text can be displayed repeatedly.

## What It Provides

Fields, domain objects, JSON, HTTP, URI, environment and process arguments, inspection,
and shared budgets. `RedactScalar` supports scalar newtypes; third-party values can
explicitly select Display representation. Unmarked fields remain ordinary output;
explicit levels belong to the business type and are not overridden by strict policy.
For hand-written domain implementations, `fields.keyed_nested(...)` keeps a public
business-key wrapper structurally redacted, so rules inside its nested payload still apply.
Disabled policy is a raw-value debugging escape hatch. The library does not erase source
memory or protect output that bypasses its redaction entry points.

`max_serde_payload_bytes` bounds logical scalar payloads in structured Serde;
`max_output_bytes` bounds final text or `to_json()` JSON retained by the library.
Both default to 16 KiB and are independent. When serializing a view or derived source directly,
the caller's serializer/writer controls final encoded length. See the guide's budget matrix.

## Learn More

See the [English user guide](doc/user_guide.md) and [Chinese user guide](doc/user_guide.zh_CN.md)
for feature configuration, complete attribute/type tables, policy precedence, HTTP, and
batch scenarios. See also the [derive guide](derive/README.md) and [API docs](https://docs.rs/qubit-redact).

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
