# Qubit Redact

[![Rust CI](https://github.com/qubit-ltd/rs-sanitize/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-sanitize/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-sanitize/coverage-badge.json)](https://qubit-ltd.github.io/rs-sanitize/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact.svg?color=blue)](https://crates.io/crates/qubit-redact)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![English Document](https://img.shields.io/badge/Document-English-blue.svg)](README.md)

面向 Rust 诊断信息、结构化字段、Map、进程参数、环境变量及可选 HTTP 数据的策略化
遮盖库。

## 设计

Qubit Redact 将职责拆成四层：

- `RedactionPolicy` 是字段规则、允许规则、匹配方式和掩码的不可变快照。
- `Redactor` 使用一份策略处理标量字段值和字符串 Map。
- `ArgvRedactor`、`EnvRedactor` 生成有类型且日志安全的进程诊断结果。
- 可选 `http` 模块处理 URL、form、header 和有界 body。

未知字段会原样通过。因此，本库依靠已知结构和已配置字段名，而不是尝试通用地发现
秘密。默认策略提供保守的预定义规则，builder 可增加业务规则和显式允许决策。

## Cargo Feature

默认 feature 集为空，核心 crate 没有外部运行时依赖。

| Feature | 能力 | 可选依赖 |
| --- | --- | --- |
| `http` | URL、form、header 和有界 body 遮盖 | `form_urlencoded`、`http`、`serde_json`、`url` |

```toml
[dependencies]
qubit-redact = "0.1"

# 仅在需要 HTTP 能力的 crate 中启用。
qubit-redact-http = { package = "qubit-redact", version = "0.1", features = ["http"] }
```

## 标量与 Map

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

`redact_map_in_place` 提供对应的原地修改操作。两个 Map 方法都根据 key 分类 value，
并保留安全值。

## 策略配置

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

`raise` 不会削弱已有规则。只有明确需要替换（包括降级）时才使用
`override_level`。精确允许规则只作用于完整字段；后缀允许规则的披露范围更广，应谨慎
使用。

## 进程诊断

`ArgvRedactor::redact_items` 信任调用方提供的敏感等级，不推断命令行语法。
`redact_heuristically` 会额外识别常见 option 和赋值形式，但不会把 shell payload 当作
脚本解析。

`EnvRedactor` 处理 UTF-8 pair；任一操作系统组件不是合法 UTF-8 时会安全关闭。结果可
安全显示为 `NAME=VALUE`。
自定义 `Debug` 实现需要隐藏捕获值时，可使用 `redacted_debug` 固定输出
`<redacted>`；该 wrapper 绝不会调用被包装值自身的 `Debug` 实现。

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

## HTTP 遮盖

启用 `http` 后可使用 `HttpRedactor`。它持有不可变 `HttpRedactionPolicy`，提供 URL、
URL-encoded form、header 和 body 操作。`BodyCapture` 区分完整输入和受检的截断输入，
`BodyBudget` 同时限制解析输入和渲染输出。

不合法或已截断的结构化 body 会安全关闭。不透明文本、无 key 的 JSON 标量、文件
part、匿名 multipart part 和 URL path 默认采用保守策略。HTTP 结果类型只暴露日志
安全文本，不提供原始 body 逃生口。

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

`TextBodyPolicy::PassThrough`、`UnkeyedJsonValuePolicy::PassThrough` 和
`UrlPathPolicy::Preserve` 都是显式诊断 opt-in。只有应用已经接受相应信息披露风险时才
应选择它们。

## 安全边界

- 字段名会被规范化，可选择精确或 token 后缀匹配。
- 允许规则会有意胜出并可能暴露数据，应把它们作为安全策略审查。
- 本库不会发现保存在未知字段名下的秘密。
- `RedactedText` 表示字段值已按策略处理；`LogSafeText` 还会转义控制字符和 Unicode
  行序字符。
- 应把有类型的显示结果作为日志边界，不要再用原始输入拼接字符串。

## 测试

```bash
# 使用默认 feature 集运行测试
cargo test

# 使用项目声明的全部 feature 运行测试
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
