# Qubit Sanitize

[![Rust CI](https://github.com/qubit-ltd/rs-sanitize/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-sanitize/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-sanitize/coverage-badge.json)](https://qubit-ltd.github.io/rs-sanitize/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-sanitize.svg?color=blue)](https://crates.io/crates/qubit-sanitize)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![中文文档](https://img.shields.io/badge/文档-中文版-blue.svg)](README.zh_CN.md)

Reusable sanitization utilities for Rust.

## Overview

Qubit Sanitize provides reusable tools for masking known sensitive data in
logs, diagnostics, and structured debug output. The core layer handles the common
field-value problem shared by HTTP clients, command runners, configuration
objects, and other crates: given a `(field, value)` pair, decide whether the
field name is configured as sensitive and return a masked value to display.

The adapter layer builds on that core policy for common structured inputs such
as URLs, URL-encoded forms, HTTP headers, HTTP bodies, argv vectors, and
environment variables. Adapters parse only the formats they explicitly model;
shell command strings and other application-specific protocols should still be
handled by caller crates that have the full context.

## Features

- Field-name canonicalization for separator-insensitive matching
- Built-in sensitive field defaults for credentials, tokens, HTTP auth, cookies,
  and sessions
- Configurable sensitivity levels: `Low`, `Medium`, `High`, and `Secret`
- Level-specific masking through `MaskPolicies`
- Mask strategies for fixed replacement, edge preservation, suffix
  preservation, and full removal
- A `FieldSanitizer` object that sanitizes single field-value pairs
- Convenience helpers for sanitizing `BTreeMap<String, String>` values by key
- Adapters for URLs, URL-encoded forms, HTTP headers, HTTP bodies, argv
  vectors, and environment variables

## Cargo Features

The core field-matching API plus argv and environment adapters are always
available and have no external dependencies. The default feature selection
also enables the complete web and HTTP adapter API. Consumers that only need
the dependency-free surface can disable defaults.

| Feature | Includes | Optional dependencies |
| --- | --- | --- |
| Always compiled | Field policies, masking, argv, and environment adapters | None |
| `web` | URL and URL-encoded form adapters | `url`, `form_urlencoded` |
| `http` | HTTP header and body adapters | `http`, `serde_json`, `form_urlencoded` |

For example, a command runner can depend only on the core surface:

```toml
qubit-sanitize = { version = "0.3", default-features = false }
```

## Quick Start

```rust
use qubit_sanitize::{
    FieldSanitizer,
    NameMatchMode,
};

let sanitizer = FieldSanitizer::default();

assert_eq!(
    sanitizer.sanitize_value(
        "password",
        "correct-horse-battery-staple",
        NameMatchMode::Exact,
    ),
    "<redacted>",
);
assert_eq!(
    sanitizer.sanitize_value("mode", "debug", NameMatchMode::Exact),
    "debug",
);
```

## Sensitivity Levels

Sensitive fields are assigned one of four levels:

| Level | Intended use | Default mask |
| --- | --- | --- |
| `Low` | Values where a small prefix and suffix help diagnostics | `ab****yz` |
| `Medium` | Identifiers where only the tail should remain visible | `****z` |
| `High` | Tokens or API keys that should not expose edges | `****` |
| `Secret` | Passwords, private keys, or client secrets | `<redacted>` |

The defaults are conservative for operational logs. You can replace any level's
masking strategy through `MaskPolicies`.

## Mask Policies

```rust
use qubit_sanitize::MaskPolicy;

let edge = MaskPolicy::preserve_edges(2, 2, "****", 4);
assert_eq!(edge.mask("abcdefgh"), "ab****gh");

let suffix = MaskPolicy::preserve_suffix(4, "****", 4);
assert_eq!(suffix.mask("1234567890"), "****7890");

let fixed = MaskPolicy::fixed("****");
assert_eq!(fixed.mask("secret"), "****");
```

Empty values are kept empty. This avoids changing the semantics of fields that
are present but intentionally blank.

## Sensitive Fields

`SensitiveFields::default()` contains a starter set of common sensitive names
such as:

- `password`, `passwd`, `passphrase`, `pgpassword`, `secret`, `client_secret`
- `private_key`, `security_key`, `mysql_pwd`, `rediscli_auth`
- `database_url`, `database_uri`, `connection_string`
- `api_key`, `x_api_key`
- `token`, `access_token`, `refresh_token`, `id_token`
- `authorization`, `proxy_authorization`, `cookie`, `set_cookie`
- `session`, `session_id`, `session_token`

The default list is not an exhaustive secret detector. Applications should add
their own protocol and business field names. Field names are canonicalized
before lookup. Separators such as `_`, `-`, `.`, and whitespace are ignored,
and names are lowercased:

```rust
use qubit_sanitize::canonicalize_field_name;

assert_eq!(canonicalize_field_name(" access-token "), "accesstoken");
assert_eq!(canonicalize_field_name("access_token"), "accesstoken");
assert_eq!(canonicalize_field_name("access.token"), "accesstoken");
```

## Name Matching Modes

Core methods such as `sanitize_value` and `sanitize_map` require callers to
choose a field-name matching mode. Use `NameMatchMode::Exact` for exact
canonical field-name matching. For contextual names where callers want
`OPENAI_API_KEY` to match the configured field `api_key`, use
`NameMatchMode::ExactOrSuffix`. Suffix matching observes separator and camel-case
token boundaries: `openaiApiKey` and `OPENAI_API_KEY` can match `api_key`, while
an unrelated single token such as `notapikey` does not.

```rust
use qubit_sanitize::{
    FieldSanitizer,
    NameMatchMode,
};

let sanitizer = FieldSanitizer::default();

assert_eq!(
    sanitizer.sanitize_value(
        "OPENAI_API_KEY",
        "abcdef",
        NameMatchMode::Exact,
    ),
    "abcdef",
);
assert_eq!(
    sanitizer.sanitize_value(
        "OPENAI_API_KEY",
        "abcdef",
        NameMatchMode::ExactOrSuffix,
    ),
    "****",
);
```

## Custom Fields

```rust
use qubit_sanitize::{
    FieldSanitizer,
    NameMatchMode,
    SensitivityLevel,
};

let mut sanitizer = FieldSanitizer::default();
sanitizer.insert_sensitive_field("license_key", SensitivityLevel::Medium);

assert_eq!(
    sanitizer.sanitize_value("license-key", "abcdef", NameMatchMode::Exact),
    "****f",
);
```

`FieldSanitizer::insert_sensitive_field` and `extend_sensitive_fields` use
strongest-level semantics: adding a weaker level never downgrades an existing
field. Use `set_sensitive_field_level` only when an explicit replacement,
including a downgrade, is intended. At the lower-level `SensitiveFields` API,
`insert` and `extend` retain map-style replacement semantics, while
`insert_strongest` and `extend_strongest` prevent downgrades.

You can also start from an empty policy when you do not want built-in field
names:

```rust
use qubit_sanitize::{
    FieldSanitizePolicy,
    FieldSanitizer,
    SensitivityLevel,
};

let mut sanitizer = FieldSanitizer::new(FieldSanitizePolicy::empty());
sanitizer.insert_sensitive_field("tenant_secret", SensitivityLevel::Secret);
```

## Map Sanitization

```rust
use std::collections::BTreeMap;

use qubit_sanitize::{
    FieldSanitizer,
    NameMatchMode,
};

let sanitizer = FieldSanitizer::default();
let mut values = BTreeMap::new();
values.insert("password".to_string(), "secret".to_string());
values.insert("name".to_string(), "alice".to_string());

let sanitized = sanitizer.sanitize_map(&values, NameMatchMode::Exact);

assert_eq!(sanitized["password"], "<redacted>");
assert_eq!(sanitized["name"], "alice");
assert_eq!(values["password"], "secret");
```

For mutable structured data, use `sanitize_map_in_place` with an explicit
`NameMatchMode`.

## Redacted Debug Fields

Use `redacted_debug` when a custom `Debug` implementation must expose object
structure without formatting a sensitive field. The wrapper never calls the
wrapped value's `Debug` implementation:

```rust
use qubit_sanitize::redacted_debug;

let captured_bytes = b"secret output";
assert_eq!(format!("{:?}", redacted_debug(captured_bytes)), "<redacted>");
```

## Adapter Sanitization

```rust
use qubit_sanitize::{
    ArgvSanitizer,
    FormUrlEncodedSanitizer,
    HttpBodySanitizer,
    HttpHeaderSanitizer,
    NameMatchMode,
    UrlSanitizer,
};
use http::header::AUTHORIZATION;
use http::HeaderValue;

let url = UrlSanitizer::default()
    .sanitize_url_str(
        "https://alice:secret@example.com/path?access_token=abcdef#callback",
        NameMatchMode::ExactOrSuffix,
    )
    .expect("sample URL should parse");
assert_eq!(
    url,
    "https://****:%3Credacted%3E@example.com/path?access_token=****#****",
);

let form = FormUrlEncodedSanitizer::default()
    .sanitize_str("username=alice&password=secret", NameMatchMode::ExactOrSuffix);
assert_eq!(form, "username=alice&password=%3Credacted%3E");

let header = HttpHeaderSanitizer::default()
    .sanitize_value(
        &AUTHORIZATION,
        &HeaderValue::from_static("Bearer abcdef"),
        NameMatchMode::ExactOrSuffix,
    );
assert_eq!(header, "****");

let body_content_type = HeaderValue::from_static("application/json");
let body = HttpBodySanitizer::default().sanitize_body(
    br#"{"user":"alice","password":"secret"}"#,
    Some(&body_content_type),
    NameMatchMode::ExactOrSuffix,
);
assert_eq!(
    body.to_string(),
    r#"{"password":"<redacted>","user":"alice"}"#,
);

let argv = ArgvSanitizer::default()
    .sanitize_argv_display(
        ["docker", "login", "--password", "secret"],
        NameMatchMode::ExactOrSuffix,
    );
assert_eq!(argv, r#"["docker", "login", "--password", "<redacted>"]"#);
```

Adapter methods require an explicit `NameMatchMode`, just like the core
`FieldSanitizer` methods. Use `NameMatchMode::ExactOrSuffix` when contextual
names such as `OPENAI_API_KEY` should match the configured field `api_key`.

`UrlSanitizer` masks userinfo and fragments with the `High` policy, passwords
with the `Secret` policy, and configured query parameters by their resolved
field level. It deliberately leaves the URL path unchanged: path segment
semantics are application-specific, including vendor-specific webhook or token
segments. Callers that know such a route must redact or replace its path before
logging it.

## Integration Guidance

The crate has two layers:

- Use `core` / root exports such as `FieldSanitizer` for field-name matching
  and value masking.
- Use `adapter` / root exports such as `UrlSanitizer`, `HttpBodySanitizer`, and
  `ArgvSanitizer` for supported structured inputs.
- Keep protocol-specific parsing in caller crates when the adapter cannot model
  the full context, especially shell command strings and application-specific
  payloads.

For example, an HTTP crate can use `UrlSanitizer` for parsed URLs and
`HttpHeaderSanitizer` for `http::HeaderMap` and `http::HeaderValue` values. It
can use `HttpBodySanitizer` when it has body bytes plus an optional
`Content-Type` header; the adapter supports JSON, NDJSON, URL-encoded forms,
multipart bodies, declared `text/*` bodies, and binary fallback markers.
Unsupported UTF-8 media types are redacted rather than passed through. The
returned `BodySanitization` exposes sanitized `content`, a structured `status`,
and captured/source byte lengths. Its `Display` implementation and
`into_rendered` add the standard counted truncation suffix; `into_content`
omits that suffix for callers with context-specific rendering. The diagnostic
content is not a replayable HTTP body: structured output may be compacted and
may not preserve original whitespace, field order, or JSON value types for
redacted fields. The caller still owns capture limits, decompression, streaming
boundaries, and any application-specific parsing.

```rust
use http::HeaderValue;
use qubit_sanitize::{HttpBodySanitizer, NameMatchMode};

let prefix = br#"{"password":"secret"#;
let source_len = 40;
let content_type = HeaderValue::from_static("application/json");
let result = HttpBodySanitizer::default().sanitize_body_preview(
    prefix,
    source_len,
    Some(&content_type),
    NameMatchMode::ExactOrSuffix,
);

assert_eq!(result.truncated_bytes(), source_len - prefix.len());
assert!(!result.content().contains("secret"));
println!("{result}");
```

A command runner can use `ArgvSanitizer` for structured argv and
`EnvSanitizer` for explicit environment overrides, but should not claim to
safely parse arbitrary shell scripts.

### Opaque Text Bodies

`HttpBodySanitizer` redacts declared `text/*` bodies and non-sensitive
multipart text parts by default. They do not contain reliable field structure,
so field-name matching cannot determine whether a value is secret. Select
`TextBodyPolicy::PassThrough` only when the caller accepts responsibility for
the original text, including application secrets and log-control content:

```rust
use qubit_sanitize::{
    HttpBodySanitizer,
    TextBodyPolicy,
};

let sanitizer = HttpBodySanitizer::default()
    .with_text_body_policy(TextBodyPolicy::PassThrough);
```

Neither policy scans arbitrary text. Similarly, a business secret stored inside
a non-sensitive structured field is outside the guarantee of field-name-based
sanitization.

## Testing

A minimal local run:

```bash
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

To mirror what continuous integration enforces, run the repository scripts from
the project root: `./align-ci.sh` brings local tooling and configuration in line
with CI, then `./ci-check.sh` runs the same checks the pipeline uses. For test
coverage, use `./coverage.sh` to generate or open reports.

## Contributing

Issues and pull requests are welcome.

- Keep the core focused on reusable field-value sanitization primitives.
- Keep adapters scoped to formats with clear, bounded parsing rules.
- Add or update tests when changing matching or masking behavior.
- Update this README and public rustdoc when user-visible behavior changes.
- Before submitting, run `./align-ci.sh` and then `./ci-check.sh`.

By contributing, you agree to license your contributions under the
[Apache License, Version 2.0](LICENSE), the same license as this project.

## License

Copyright © 2026 Haixing Hu, Qubit Co. Ltd.

This project is licensed under the [Apache License, Version 2.0](LICENSE). See
the `LICENSE` file in the repository for the full text.

## Author

**Haixing Hu** — Qubit Co. Ltd.

| | |
| --- | --- |
| **Repository** | [github.com/qubit-ltd/rs-sanitize](https://github.com/qubit-ltd/rs-sanitize) |
| **Documentation** | [docs.rs/qubit-sanitize](https://docs.rs/qubit-sanitize) |
| **Crate** | [crates.io/crates/qubit-sanitize](https://crates.io/crates/qubit-sanitize) |
