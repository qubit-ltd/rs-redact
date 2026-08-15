# Qubit Redact

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact.svg?color=blue)](https://crates.io/crates/qubit-redact)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![English Document](https://img.shields.io/badge/Document-English-blue.svg)](README.md)

Qubit Redact 用于防止敏感信息经 Rust 诊断信息泄露，包括日志、`Debug` 输出、进程参数、
环境变量和可选的 HTTP trace。一次定义不可变策略，再在明确的日志安全边界渲染有类型的结果。

## 为什么选择 Qubit Redact

- 一套策略模型可分类标量值、Map、领域对象、进程诊断和可选 HTTP 数据中的具名字段。
- 有类型的结果明确区分“值已脱敏”和“文本可安全写入日志”。
- 不合法或已截断的结构化 HTTP 输入会失败时默认遮盖（fail closed）；有限预算限制检查、
  输出、JSON 递归深度和信息披露。
- 一个不可变的 `RedactionPolicy` 统一拥有基础字段、HTTP/URI 上下文覆盖、掩码和静态
  限制。嵌套诊断值共享同一个 `RedactionSession`，子值不能重置父级预算。
- URI 脱敏保留原始 scheme、authority、path、query 顺序和编码，同时按核心策略分别处理
  username/password、query 值以及可配置的 path/fragment 边界。
- 默认 feature 集为空；HTTP、JSON、URI 和 Serde 集成均需显式启用。

## 快速开始

```toml
[dependencies]
qubit-redact = "0.5"
```

```rust
use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = RedactionPolicy::builder();
    builder
        .fields()
        .raise("user_id", Sensitivity::Low)?
        .raise("phone_number", Sensitivity::Medium)?
        .raise("credit_card", Sensitivity::High)?
        .raise("api_key", Sensitivity::Secret)?;
    let policy = builder.build()?;
    let redactor = Redactor::new(policy);

    assert_eq!(redactor.redact_field("user_id", "alpine42").as_str(), "al****42");
    assert_eq!(redactor.redact_field("phone_number", "13800138000").as_str(), "*******0");
    assert_eq!(redactor.redact_field("credit_card", "4111111111111111").as_str(), "****");
    assert_eq!(redactor.redact_field("api_key", "sk_live_123").as_str(), "<redacted>");

    let safe = redactor
        .redact_field("display_name", "Alice\nAdmin")
        .escape_for_log();
    assert_eq!(safe.to_string(), "Alice\\nAdmin");
    Ok(())
}
```

原始值仍可供应用逻辑使用。把标量结果写入纯文本日志前，必须调用
`escape_for_log()`。

如果需要进程级默认策略，应在创建必须使用应用策略的对象之前安装已经构建好的策略：

```rust
use qubit_redact::{RedactionPolicy, Sensitivity};

let mut builder = RedactionPolicy::builder();
builder.fields().raise("api_key", Sensitivity::Secret)?;
let policy = builder.build()?;
RedactionPolicy::install_global(policy)?;
let snapshot = RedactionPolicy::default();
# Ok::<(), Box<dyn std::error::Error>>(())
```

如果没有安装策略，全局/默认策略读取会使用固定的标准策略，但不会占用全局安装槽。
提前读取后仍可调用 `install_global()`；安装只改变未来取得的快照，已有快照不会因
后续安装而改变。

一次诊断事件应创建一个 session，并在各个 adapter 之间复用。session 持有共享的输入/输出
预算，因此嵌套的 JSON、HTTP、URI、argv 和环境变量操作不会悄悄取得一份新预算：

```rust
use std::ffi::OsStr;
use qubit_redact::argv::ArgvItem;
use qubit_redact::Redactor;

let redactor = Redactor::strict();
let mut session = redactor.session();
let token = session.redact_field("token", "raw-token");
let argv = session.argv().redact_heuristically([
    ArgvItem::plain(OsStr::new("client")),
    ArgvItem::plain(OsStr::new("--token")),
    ArgvItem::plain(OsStr::new("raw-token")),
]);
assert!(!token.as_str().contains("raw-token"));
assert!(!argv.to_string().contains("raw-token"));
```

> **警告：** `install_global()` 只能由可执行应用在组装初始化阶段调用。应用应在最终
> 策略构建完成后、启动 worker 或请求处理之前调用一次；库不得调用它。安装前创建的
> 对象可能永久持有标准策略快照。必须使用应用策略的对象应在安装后创建，或显式注入
> 策略。安装前 fallback 只用于解决初始化顺序，不是运行时重配置机制。

## Derive 支持

`qubit-redact-derive` 提供过程派生宏，用于将脱敏策略应用到 Rust struct 和 enum。
`Redact` 为诊断信息创建借用的 `Redacted<T>` 视图；需要拥有式值时，`RedactMut`
执行显式的逻辑替换。它与 `qubit-redact` 运行时 crate 配合使用；完整的字段属性和
Serde/JSON 集成说明请参阅 [derive README](https://github.com/qubit-ltd/rs-redact-derive/blob/main/README.zh_CN.md) 和
[derive 用户手册](https://github.com/qubit-ltd/rs-redact-derive/blob/main/doc/user_guide.zh_CN.md)。

## 如何选择工具

| 诊断输入 | 工具 | 返回结果与日志边界 |
| --- | --- | --- |
| 具名标量值 | `Redactor::redact_field` | `RedactedText`；写入纯文本日志前调用 `escape_for_log()`。 |
| 文本 key Map | `Redactor::redact_map` 或 `redact_map_in_place` | 返回副本或修改原 Map；最终日志格式仍需由调用方处理。 |
| Rust struct 或 enum | `Redact` derive | 借用的 `Redacted<T>` 视图，支持安全格式化。 |
| 必须逻辑替换的值 | `Redact` derive | 使用同一 derive 生成的 `RedactMut` 修改对象；这不等于内存擦除。 |
| 命令行参数 | `ArgvRedactor` | 可安全显示的 `RedactedArgv`。 |
| 环境变量 pair | `EnvRedactor` | `RedactedEnvPair` 或 `LogSafeText`。 |
| URL、form、Header 或捕获的 body | `HttpRedactor` | 有界、日志安全的 HTTP 结果类型。 |
| URI 字符串 | `UriRedactor`（`uri` feature） | 带组件原因的结构化日志安全结果。 |

## Cargo Features

| 需求 | Cargo 配置 |
| --- | --- |
| 标量、Map、进程和文本 core 能力 | `qubit-redact = "0.5"` |
| 领域对象 derive | 添加 `qubit-redact-derive = "0.5"`。 |
| 序列化脱敏领域对象或视图 | 启用 `serde`，并直接声明 `serde` 依赖；`#[redact(serde)]` 让直接序列化也自动脱敏。 |
| 脱敏 `serde_json::Value` 或 JSON 文本字段 | 启用 `json`；应用使用时直接添加 `serde_json`。 |
| HTTP 诊断 | 启用 `http`；应用使用其类型时直接添加 `http`。 |
| 策略驱动 URI 脱敏 | 启用 `uri`；它与 `http` 相互独立。 |

derive 的 `#[redact(json)]` 模式会保持 JSON 文本字段的外层 Rust `String` 类型。
与 `#[redact(serde)]` 组合时，脱敏值仍会序列化为 JSON 字符串。

```toml
[dependencies]
# HTTP 诊断（包含 JSON body 支持）
qubit-redact = { version = "0.5", features = ["http"] }
http = "1.5"

# 不启用 HTTP，仅使用 URI 诊断
# qubit-redact = { version = "0.5", features = ["uri"] }
```

`json` feature 负责 JSON value 和 JSON 文本脱敏。`http` feature 会复用它处理 HTTP JSON
body，但 JSON 能力并不属于 HTTP 专属功能，也可以独立启用。

JSON 文本可以通过 `session.json()` 参与同一个事件预算：

```rust
use qubit_redact::Redactor;

let redactor = Redactor::strict();
let mut session = redactor.session();
let safe = session.json().redact_text(r#"{"token":"raw-token"}"#);
assert!(!safe.to_string().contains("raw-token"));
```

HTTP body 诊断通过 `session.http()`：

```rust
use http::HeaderValue;
use qubit_redact::http::{BodyCapture, HttpRedactor};

let redactor = HttpRedactor::default();
let mut session = redactor.session();
let content_type = HeaderValue::from_static("application/json");
let safe = session.http().redact_body(
    BodyCapture::complete(br#"{"password":"raw"}"#),
    Some(&content_type),
);
assert!(!safe.to_string().contains("raw"));
```

URI 诊断通过 `session.uri()`，并返回带状态和原因的结构化结果：

```rust
use qubit_redact::uri::UriRedactor;

let redactor = UriRedactor::default();
let mut session = redactor.session();
let safe = session.uri().redact_uri_str("https://example.test/path");
assert!(safe.log_safe_text().as_str().contains("example.test"));
```

## 安全边界

- 未知字段名默认原样通过。需要在边界遮盖所有未分类字段时，设置
  `UnknownFieldPolicy::Redact(Sensitivity::Secret)`；`classify_field()` 仍会报告 `Unknown`。
  `RedactionPolicy::strict()` 提供这一边界预设，但不会改变默认策略语义。
- 应用层 allow 规则无法绕过已启用的 `RedactionFloor`。
  `RedactionPolicy::builder()` 使用空应用规则和标准 floor；该 builder
  是确定性的，不会读取全局状态。扩展默认策略应使用
  `RedactionPolicy::default().to_builder()`。`disable_floor()` 会有意关闭全部
  floor，只应由明确承担该安全决策的调用方使用。
- 所有配置统一通过 `RedactionPolicyBuilder` 完成：使用 `fields()`、`http()`、`uri()` 和
  `limits()` 访问可变分区视图。上下文规则可以增加保护，但不能降低基础字段更强的决策。
  一个策略只有一套 masking 和 limits。
- 使用 `RedactionPolicy::install_global()` 在应用组装阶段安装一次全局策略。它只影响
  后续快照；既有 policy 与 redactor 永不随之改变。如果尚未安装，`global()` 或
  `default()` 读取固定标准策略，但不会占用安装槽。
- 脱敏领域对象/Map 视图的 `Debug` 默认使用策略的
  `limits().diagnostic_event()` 输出预算。派生嵌套值、Map、JSON 文本和显式 adapter
  session 共享同一个 `RedactionSession`，子值不能隐式取得一份新预算。
- `InputOutputLimit` 是不可变策略设置；`RedactionSession` 是每个 operation 或
  diagnostic event 使用的、不可克隆的运行时计量对象。多个 adapter 应复用同一个
  session；输出由 adapter 提交计量，fallback 标记不能绕过累计上限。
- `redact_field()` 返回 `FieldRedaction`，区分已遮盖、允许直通和未知字段直通。
- `RedactedText` 故意不实现 `Display`。值脱敏与日志转义是两层不同保证。
- 领域对象或 Map 视图的 `Debug` 与日志安全 `Display` 默认都受策略诊断输出预算限制；
  需要不同的显式限制时使用 `with_output_limit()`。
- `RedactMut` 只替换逻辑值，不会擦除已释放的分配内存、别名、副本或借用后备存储。
- URI 脱敏通过 `qubit_redact::uri::UriRedactor` 显式启用。userinfo 只在第一个原始 `:`
  处分割；用户名使用 `username` 字段规则，密码使用 `password` 字段规则。query key
  会严格解码后分类，未遮盖的值保留原始百分号编码。URI 语法无效或 query 组件无法解码时
  返回固定标记。
- JSON 脱敏到达 `JsonDepthLimit` 后，会用策略的 Secret 不透明掩码替换超深子树；
  默认最大深度为 128。
- HTTP 脱敏只处理调用方提供的 capture，绝不会自行读取或缓存网络 body。HTTP 行为配置在
  根部 `RedactionPolicy` 上，由 `HttpRedactor` 使用该快照。

## 深入了解

- [English User Guide](doc/user_guide.md) 和[中文用户手册](doc/user_guide.zh_CN.md)
- [Runtime API 文档](https://docs.rs/qubit-redact)
- [qubit-redact-derive README](https://github.com/qubit-ltd/rs-redact-derive/blob/main/README.zh_CN.md)：字段属性和 serde 支持
- [qubit-redact-derive 用户手册](https://github.com/qubit-ltd/rs-redact-derive/blob/main/doc/user_guide.zh_CN.md)
- [derive crate API 文档](https://docs.rs/qubit-redact-derive)

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

仓库地址：[https://github.com/qubit-ltd/rs-redact](https://github.com/qubit-ltd/rs-redact)
