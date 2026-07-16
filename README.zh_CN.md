# Qubit Sanitize

[![Rust CI](https://github.com/qubit-ltd/rs-sanitize/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-sanitize/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-sanitize/coverage-badge.json)](https://qubit-ltd.github.io/rs-sanitize/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-sanitize.svg?color=blue)](https://crates.io/crates/qubit-sanitize)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![English Document](https://img.shields.io/badge/Document-English-blue.svg)](README.md)

Rust 通用脱敏工具。

## 概览

Qubit Sanitize 提供一组用于遮盖已知敏感数据的可复用工具，面向日志、诊断信息和结构化 Debug
输出。core 层解决多个 crate 都会重复遇到的共性问题：给定一个 `(field, value)`
字段名和值，判断字段名是否被配置为敏感字段，并返回适合展示的掩码值。

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

core 字段匹配 API、argv 和环境变量 adapter 始终可用，并且没有外部依赖。默认 feature
还会启用完整的 web 和 HTTP adapter API。只需要无依赖能力的调用方可以关闭默认
feature。

| Feature | 包含内容 | 可选依赖 |
| --- | --- | --- |
| 始终编译 | 字段策略、掩码、argv 和环境变量 adapter | 无 |
| `web` | URL 和 URL-encoded form adapter | `url`、`form_urlencoded` |
| `http` | HTTP header 和 body adapter | `http`、`serde_json`、`form_urlencoded` |

例如，命令执行 crate 只依赖 core 能力：

```toml
qubit-sanitize = { version = "0.3", default-features = false }
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

`SensitiveFields::default()` 内置了一组常见敏感字段作为起点，例如：

- `password`、`passwd`、`secret`、`client_secret`、`private_key`、`security_key`
- `api_key`、`x_api_key`
- `token`、`access_token`、`refresh_token`、`id_token`、`sig`、`signature`
- `authorization`、`proxy_authorization`、`cookie`、`set_cookie`
- `session`、`session_id`、`session_token`

默认列表并不是穷尽式的秘密检测器，应用应补充自身协议和业务中的敏感字段名。字段名在
匹配前会先规范化：去掉 `_`、`-`、`.`、空白字符并转小写。因此下面这些
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
`NameMatchMode::ExactOrSuffix`。后缀匹配遵循分隔符和驼峰词元边界：
`openaiApiKey`、`OPENAI_API_KEY` 可以命中 `api_key`，而无关的单一词元
`notapikey` 不会命中。

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

`FieldSanitizer::insert_sensitive_field` 和 `extend_sensitive_fields` 使用最强等级
语义：添加较弱等级不会降低已有字段。只有明确需要覆盖（包括降级）时才使用
`set_sensitive_field_level`。更底层的 `SensitiveFields::insert` 和 `extend` 保留
map 风格的覆盖语义；`insert_strongest` 和 `extend_strongest` 则保证不降级。

应用确认某个默认字段属于误报后，可以将其删除。删除默认项是一项显式的信息披露
决策：此后匹配值会保持原样。

```rust
use qubit_sanitize::{FieldSanitizer, NameMatchMode};

let mut sanitizer = FieldSanitizer::default();
sanitizer.remove_sensitive_field("sig");

assert_eq!(
    sanitizer.sanitize_value("sig", "known-safe", NameMatchMode::Exact),
    "known-safe",
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

## Debug 字段脱敏

自定义 `Debug` 实现如果需要展示对象结构、但不能格式化某个敏感字段，可以使用
`redacted_debug`。该 wrapper 不会调用被包装值的 `Debug` 实现：

```rust
use qubit_sanitize::redacted_debug;

let captured_bytes = b"secret output";
assert_eq!(format!("{:?}", redacted_debug(captured_bytes)), "<redacted>");
```

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

adapter 方法也和 core 的 `FieldSanitizer` 一样要求显式传入 `NameMatchMode`。如果
希望 `OPENAI_API_KEY` 这类上下文字段名命中已配置的 `api_key`，使用
`NameMatchMode::ExactOrSuffix`。

`UrlSanitizer` 使用 `High` 策略遮盖 userinfo 和 fragment，使用 `Secret` 策略遮盖
password，并按已解析出的字段等级遮盖 query parameter；它会有意保留 URL path。
path segment 的语义属于具体应用，其中也包括供应商自定义的 webhook 或 token 路径。
掌握这类路由语义的调用方必须在记录日志前自行遮盖或替换 path。

URL query 和 URL-encoded form 中，如果百分号转义格式错误，或解码后不是 UTF-8，
会整体脱敏。这个 fail-closed 行为可以防止歧义解码绕过字段名匹配。

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
返回的 `BodySanitization` 提供脱敏后的 `content`、结构化 `status`，以及已捕获/来源
字节数。它的 `Display` 和 `into_rendered` 会追加标准的计数截断后缀；
`into_content` 则不追加，便于调用方使用自己的上下文后缀。诊断内容不是可回放的
HTTP body：结构化输出可能会被压缩，也不保证保留原始空白、字段顺序，或已脱敏 JSON
字段的原始 value 类型。调用方仍然负责 body 捕获上限、解压、流式边界和业务自定义
解析。

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

命令执行 crate 可以用 `ArgvSanitizer` 处理结构化 argv，用 `EnvSanitizer` 处理显式
环境变量覆盖，但不应宣称可以安全解析任意 shell 脚本。

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

```bash
# 使用默认的空 feature 集测试核心 API
cargo test --no-default-features

# 测试核心 API 和正则校验
cargo test --all-features

# 运行项目 CI 检查
./ci-check.sh

# 检查代码覆盖率
./coverage.sh
```

## 许可证

Copyright (c) 2025 - 2026. Haixing Hu. All rights reserved.

本项目基于 Apache License 2.0 授权。完整许可证文本请参阅
[LICENSE](LICENSE)。

## 贡献

欢迎贡献。请遵循 Rust API 指南，及时更新公共 API 文档与测试，并在提交
Pull Request 前运行 `./align-ci.sh`格式化代码，运行`./ci-check.sh`对齐CI要求。

## 作者

**Haixing Hu** - *Qubit Co. Ltd.*

仓库地址：[https://github.com/qubit-ltd/rs-sanitize](https://github.com/qubit-ltd/rs-sanitize)
