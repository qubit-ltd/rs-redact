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
- 默认 feature 集为空，核心 crate 没有外部运行时依赖。

## 快速开始

```toml
[dependencies]
qubit-redact = "0.5"
```

```rust
use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = RedactionPolicy::builder()
        .raise("user_id", Sensitivity::Low)
        .raise("phone_number", Sensitivity::Medium)
        .raise("credit_card", Sensitivity::High)
        .raise("api_key", Sensitivity::Secret)
        .build()?;
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

## 如何选择工具

| 诊断输入 | 工具 | 返回结果与日志边界 |
| --- | --- | --- |
| 具名标量值 | `Redactor::redact_field` | `RedactedText`；写入纯文本日志前调用 `escape_for_log()`。 |
| 文本 key Map | `Redactor::redact_map` 或 `redact_map_in_place` | 返回副本或修改原 Map；最终日志格式仍需由调用方处理。 |
| Rust struct 或 enum | `Redact` derive | 借用的 `Redacted<T>` 视图，支持安全格式化。 |
| 必须逻辑替换的值 | `RedactMut` derive | 已修改对象；这不等于内存擦除。 |
| 命令行参数 | `ArgvRedactor` | 可安全显示的 `RedactedArgv`。 |
| 环境变量 pair | `EnvRedactor` | `RedactedEnvPair` 或 `LogSafeText`。 |
| URL、form、Header 或捕获的 body | `HttpRedactor` | 有界、日志安全的 HTTP 结果类型。 |

## Cargo Features

| 需求 | Cargo 配置 |
| --- | --- |
| 标量、Map、进程和文本 core 能力 | `qubit-redact = "0.5"` |
| 领域对象 derive | 添加 `qubit-redact-derive = "0.5"`。 |
| 序列化脱敏视图 | 启用 `serde`，并直接声明 `serde` 依赖。 |
| 脱敏 `serde_json::Value` 或 JSON 文本字段 | 启用 `json`；应用使用时直接添加 `serde_json`。 |
| HTTP 诊断 | 启用 `http`；应用使用其类型时直接添加 `http`。 |

```toml
[dependencies]
# 仅启用 HTTP 诊断
qubit-redact = { version = "0.5", features = ["http"] }
http = "1.4"
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
- 进程级 floor 和 policy 默认值只能安装一次，只影响未来快照；既有 policy 与 redactor
  永不随之改变。
- `redact_field()` 返回 `FieldRedaction`，区分已遮盖、允许直通和未知字段直通。
- `RedactedText` 故意不实现 `Display`。值脱敏与日志转义是两层不同保证。
- 需要让领域对象或 Map 视图受策略诊断预算限制时，调用
  `with_policy_output_limit()`；其 `Debug` 和 `Display` 输出都会有界且适合日志。
- `RedactMut` 只替换逻辑值，不会擦除已释放的分配内存、别名、副本或借用后备存储。
- JSON 脱敏到达 `JsonDepthBudget` 后，会用策略的 Secret 不透明掩码替换超深子树；
  默认最大深度为 128。
- HTTP 脱敏只处理调用方提供的 capture，绝不会自行读取或缓存网络 body。
  `HttpRedactionPolicy` 应从 `qubit_redact::http` 导入，而非 HTTP 客户端 crate。

## 深入了解

- [English User Guide](doc/user_guide.md) 和[中文用户手册](doc/user_guide.zh_CN.md)
- [Runtime API 文档](https://docs.rs/qubit-redact)
- [derive crate README](derive/README.zh_CN.md)：字段属性和 serde 支持
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
