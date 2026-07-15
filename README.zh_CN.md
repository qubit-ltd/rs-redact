# Qubit Sanitize

[![Rust CI](https://github.com/qubit-ltd/rs-sanitize/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-sanitize/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-sanitize/coverage-badge.json)](https://qubit-ltd.github.io/rs-sanitize/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-sanitize.svg?color=blue)](https://crates.io/crates/qubit-sanitize)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![English](https://img.shields.io/badge/docs-English-blue.svg)](README.md)

Rust 通用脱敏工具。

## 概览

Qubit Sanitize 提供一组可复用的脱敏工具，面向日志、诊断信息和结构化 Debug
输出。core 层解决多个 crate 都会重复遇到的共性问题：给定一个 `(field, value)`
字段名和值，判断这个字段是否敏感，并返回适合展示的安全值。

adapter 层在 core 策略之上处理常见结构化输入，例如 URL、URL-encoded form、
HTTP header、HTTP body、argv 向量和环境变量。adapter 只解析自己明确建模的格式；
shell 命令字符串和其他业务协议 payload 仍应由掌握完整上下文的调用方 crate 处理。

## 特性

- 字段名规范化，支持忽略常见分隔符后匹配
- 内置凭证、token、HTTP 认证、cookie、session 等常见敏感字段
- 可配置敏感级别：`Low`、`Medium`、`High`、`Secret`
- 每个敏感级别可以绑定不同的 `MaskPolicy`
- 支持固定替换、保留首尾、保留尾部、完全移除等脱敏策略
- `FieldSanitizer` 对象专注处理单个字段值脱敏
- 提供 `BTreeMap<String, String>` 的复制式和原地脱敏便捷方法
- 提供 URL、URL-encoded form、HTTP header、HTTP body、argv 向量和环境变量 adapter

## Cargo Feature

默认 feature 保持当前完整 API。只需要通用字段匹配的调用方可以关闭默认 feature，避免
引入 HTTP、JSON 和 URL 依赖。

| Feature | 包含内容 | 可选依赖 |
| --- | --- | --- |
| `core` | 字段策略、掩码、argv 和环境变量 adapter | 无 |
| `web` | `core`、URL 和 URL-encoded form adapter | `url`、`form_urlencoded` |
| `http` | `core`、HTTP header 和 body adapter | `http`、`serde_json`、`form_urlencoded` |

例如，命令执行 crate 只依赖 core 能力：

```toml
qubit-sanitize = { version = "0.2", default-features = false, features = ["core"] }
```

## 快速开始

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

## 敏感级别

敏感字段可以配置为四个级别：

| 级别 | 适用场景 | 默认脱敏结果 |
| --- | --- | --- |
| `Low` | 可以保留少量首尾字符辅助排查的低风险值 | `ab****yz` |
| `Medium` | 只适合保留尾部一小段的标识类值 | `****z` |
| `High` | token、API key 等不应暴露首尾的值 | `****` |
| `Secret` | 密码、私钥、client secret 等最高风险值 | `<redacted>` |

默认策略面向运行日志偏保守。如果某个业务场景需要不同展示方式，可以替换
`MaskPolicies` 中任意级别对应的策略。

## 脱敏策略

```rust
use qubit_sanitize::MaskPolicy;

let edge = MaskPolicy::preserve_edges(2, 2, "****", 4);
assert_eq!(edge.mask("abcdefgh"), "ab****gh");

let suffix = MaskPolicy::preserve_suffix(4, "****", 4);
assert_eq!(suffix.mask("1234567890"), "****7890");

let fixed = MaskPolicy::fixed("****");
assert_eq!(fixed.mask("secret"), "****");
```

空值会保持为空。这样可以保留“字段存在但值为空”的语义，同时不泄露敏感内容。

## 敏感字段

`SensitiveFields::default()` 内置了一组常见敏感字段，例如：

- `password`、`passwd`、`secret`、`client_secret`、`private_key`
- `api_key`、`x_api_key`
- `token`、`access_token`、`refresh_token`、`id_token`
- `authorization`、`proxy_authorization`、`cookie`、`set_cookie`
- `session`、`session_id`、`session_token`

字段名在匹配前会先规范化：去掉 `_`、`-`、`.`、空白字符并转小写。因此下面这些
名字会匹配到同一个字段：

```rust
use qubit_sanitize::canonicalize_field_name;

assert_eq!(canonicalize_field_name(" access-token "), "accesstoken");
assert_eq!(canonicalize_field_name("access_token"), "accesstoken");
assert_eq!(canonicalize_field_name("access.token"), "accesstoken");
```

## 字段名匹配模式

`sanitize_value`、`sanitize_map` 等 core 方法要求调用方显式选择字段名匹配模式。
如果需要规范化后的精确字段名匹配，使用 `NameMatchMode::Exact`；如果希望
`OPENAI_API_KEY` 这类带上下文前缀的名字命中已配置的 `api_key`，使用
`NameMatchMode::ExactOrSuffix`。

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

## 自定义字段

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

如果不想使用内置字段，可以从空策略开始：

```rust
use qubit_sanitize::{
    FieldSanitizePolicy,
    FieldSanitizer,
    SensitivityLevel,
};

let mut sanitizer = FieldSanitizer::new(FieldSanitizePolicy::empty());
sanitizer.insert_sensitive_field("tenant_secret", SensitivityLevel::Secret);
```

## Map 脱敏

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

如果需要直接修改已有结构，可以使用 `sanitize_map_in_place`，并显式传入
`NameMatchMode`。

## Adapter 脱敏

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
    "https://****:****@example.com/path?access_token=****#****",
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
assert_eq!(body, r#"{"password":"<redacted>","user":"alice"}"#);

let argv = ArgvSanitizer::default()
    .sanitize_argv_display(
        ["docker", "login", "--password", "secret"],
        NameMatchMode::ExactOrSuffix,
    );
assert_eq!(argv, r#"["docker", "login", "--password", "<redacted>"]"#);
```

adapter 方法也和 core 的 `FieldSanitizer` 一样要求显式传入 `NameMatchMode`。如果
希望 `OPENAI_API_KEY` 这类上下文字段名命中已配置的 `api_key`，使用
`NameMatchMode::ExactOrSuffix`。

## 集成建议

这个 crate 分为两层：

- 使用 `core` 或根导出的 `FieldSanitizer` 等类型处理字段名匹配和值脱敏。
- 使用 `adapter` 或根导出的 `UrlSanitizer`、`HttpBodySanitizer`、`ArgvSanitizer`
  等类型处理已支持的结构化输入。
- 当 adapter 无法完整建模上下文时，协议相关解析仍应放在调用方 crate，尤其是
  shell 命令字符串和业务自定义 payload。

例如，HTTP crate 可以用 `UrlSanitizer` 处理解析后的 URL，用
`HttpHeaderSanitizer` 处理 `http::HeaderMap` 和 `http::HeaderValue`。当调用方有 body
字节和可选 `Content-Type` header 时，可以用 `HttpBodySanitizer`；它支持 JSON、
NDJSON、URL-encoded form、multipart body、显式声明的 `text/*` body 以及二进制
fallback marker。不支持的 UTF-8 media type 会被整体 redaction，而不是原样透传。
body 脱敏返回值是用于日志和诊断的渲染结果，不是可回放的 HTTP body：结构化输出可能
会被压缩，也不保证保留原始空白、字段顺序，或已脱敏 JSON 字段的原始 value 类型。
调用方仍然负责 body 捕获上限、解压、流式边界和业务自定义解析。命令执行 crate 可以
用 `ArgvSanitizer` 处理结构化 argv，用 `EnvSanitizer` 处理显式环境变量覆盖，但不应
宣称可以安全解析任意 shell 脚本。

### 不透明文本 body

`HttpBodySanitizer` 默认会脱敏显式声明的 `text/*` body，以及 multipart 中
非敏感的文本 part。它们没有可靠的字段结构，因此无法使用字段名匹配判断 value 是否
包含秘密。只有当调用方愿意自行承担原文中的业务秘密和日志控制字符风险时，才应显式
选择 `TextBodyPolicy::PassThrough`：

```rust
use qubit_sanitize::{
    HttpBodySanitizer,
    TextBodyPolicy,
};

let sanitizer = HttpBodySanitizer::default()
    .with_text_body_policy(TextBodyPolicy::PassThrough);
```

两种策略都不会扫描任意文本。同样地，藏在非敏感结构化字段 value 中的业务秘密，不在
基于字段名脱敏的保证范围内。

## 测试

最小本地验证：

```bash
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

如需和 CI 保持一致，请在项目根目录运行：`./align-ci.sh` 会对齐本地工具和配置，
然后 `./ci-check.sh` 执行与流水线一致的完整检查。覆盖率报告可通过
`./coverage.sh` 生成或查看。

## 贡献

欢迎提交 issue 和 pull request。

- 请保持 core 聚焦在通用字段值脱敏原语。
- adapter 只覆盖解析边界清楚、行为可测试的格式。
- 修改匹配或脱敏行为时必须增加或更新测试。
- 用户可见行为变化时同步更新 README 和公开 rustdoc。
- 提交前请运行 `./align-ci.sh` 和 `./ci-check.sh`。

贡献代码即表示你同意将贡献内容按本项目相同的
[Apache License, Version 2.0](LICENSE) 授权。

## 许可证

Copyright © 2026 Haixing Hu, Qubit Co. Ltd.

本项目基于 [Apache License, Version 2.0](LICENSE) 开源。完整许可证文本见
`LICENSE` 文件。

## 作者

**Haixing Hu** — Qubit Co. Ltd.

| | |
| --- | --- |
| **Repository** | [github.com/qubit-ltd/rs-sanitize](https://github.com/qubit-ltd/rs-sanitize) |
| **Documentation** | [docs.rs/qubit-sanitize](https://docs.rs/qubit-sanitize) |
| **Crate** | [crates.io/crates/qubit-sanitize](https://crates.io/crates/qubit-sanitize) |
