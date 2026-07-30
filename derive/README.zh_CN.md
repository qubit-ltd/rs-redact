# qubit-redact-derive

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact-derive.svg?color=blue)](https://crates.io/crates/qubit-redact-derive)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![English Document](https://img.shields.io/badge/Document-English-blue.svg)](README.md)

Qubit Redact Derive 为 [`qubit-redact`](https://crates.io/crates/qubit-redact)
运行时 crate 提供过程派生宏。它在 Rust 领域对象上定义明确的脱敏边界：
使用 `Redact` 创建安全的借用诊断视图，或使用 `RedactMut` 显式替换逻辑值。

## 为什么选择 qubit-redact-derive

- 字段属性让掩码、忽略、嵌套脱敏和 Map 脱敏在领域模型边界清晰可审查。
- 宏支持具名、tuple、unit struct，以及拥有这三种 variant 形态的 enum。
- 可选 Serde 支持仅序列化脱敏视图，不提供反序列化或回到原始值的逃生接口。
- 生成代码解析直接声明的 `qubit-redact` 依赖，支持 Cargo 重命名，而不依赖固定导入名。

## 快速开始

同时添加运行时 crate 和派生 crate：

```toml
[dependencies]
qubit-redact = "0.4"
qubit-redact-derive = "0.3"
```

```rust
use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Credentials {
    user: String,
    #[redact(level = "secret")]
    password: String,
}

fn main() {
    let credentials = Credentials {
        user: "ada".to_owned(),
        password: "raw-password".to_owned(),
    };

    let output = format!("{:?}", credentials.redacted());
    assert!(output.contains("ada"));
    assert!(!output.contains("raw-password"));
}
```

`Redact` 创建借用视图，原始 `Credentials` 仍可供应用逻辑使用。

## 如何选择派生宏

| 需求 | 派生宏 | 结果 |
| --- | --- | --- |
| 安全检查或记录领域对象，且不修改它 | `Redact` | 借用的 `Redacted<T>` 视图。 |
| 序列化已脱敏对象 | 带 `#[redact(serde)]` 的 `Redact` | 为 `Redacted<T>` 显式生成 `Serialize`。 |
| 在进入下一边界前替换拥有的逻辑值 | `RedactMut` | 显式调用 `redact_in_place()` 或 `redact_in_place_with(...)`。 |
| 让原类型通过进程默认策略格式化 | 带 `#[redact(debug)]` 或 `#[redact(display)]` 的 `Redact` | 为原类型生成 `Debug` 和/或 `Display`。 |

诊断场景应优先使用 `Redact`；只有下一边界必须接收逻辑替换后的值时才使用
`RedactMut`。

## 属性概览

字段属性恰好选择一种处理模式：

| 属性 | 效果 |
| --- | --- |
| `#[redact(level = "low|medium|high|secret")]` | 使用指定运行时敏感等级掩码该字段。 |
| `#[redact(skip)]` | 从脱敏视图中省略该字段。 |
| `#[redact(nested)]` | 将脱敏委托给嵌套值。 |
| `#[redact(map)]` | 使用文本 key 和完整运行时策略处理 Map 的值。 |
| `#[redact(json)]` | 递归按对象 key 脱敏存储在 `String` 中的 JSON；无效 JSON 会被不透明替换。 |

容器属性是显式选择的控制项：

| 属性 | 效果 |
| --- | --- |
| `#[redact(debug)]` | 为原类型生成脱敏 `Debug`。 |
| `#[redact(display)]` | 为原类型生成脱敏 `Display`。 |
| `#[redact(serde)]` | 为 `Redacted<T>` 生成序列化支持。 |

未标记字段使用其普通 `Debug` 表示，既不会被掩码，也不会被递归遍历。

## 依赖与 feature

生成代码要求 `qubit-redact` 是直接依赖。派生 crate 会发现 Cargo 重命名，因此下列配置
同样可用：

```toml
[dependencies]
redaction = { package = "qubit-redact", version = "0.4" }
qubit-redact-derive = "0.3"
```

使用 `#[redact(serde)]` 时，启用运行时 crate 的 `serde` feature，并直接声明
`serde`：

```toml
[dependencies]
qubit-redact = { version = "0.4", features = ["serde"] }
qubit-redact-derive = "0.3"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

`#[redact(json)]` 需要运行时 crate 的 `json` feature。它为 `Redact` 格式化脱敏 JSON
视图，为 `RedactMut` 将字符串改写为紧凑脱敏 JSON；与 `#[redact(serde)]` 组合时仍序列化为 JSON 字符串。

## 安全边界

- 宏只保护实际使用的脱敏视图、生成格式化或显式原地操作，无法保护无关的日志调用或序列化路径。
- 未标记字段使用自身的 `Debug` 输出；应标记表示中可能泄露敏感数据的每个字段。
- `skip` 只从脱敏表示中省略值，不会擦除原始值。
- `RedactMut` 只做逻辑替换，不会擦除已释放的分配内存、别名、副本或借用后备存储。
- `debug` 和 `display` 使用进程级默认策略；调用点需要策略隔离时，应显式使用
  `redacted_with` 边界。

## 深入了解

- [English User Guide](doc/user_guide.md) 和[中文用户手册](doc/user_guide.zh_CN.md)
- [运行时 README](../README.zh_CN.md) 和[运行时用户手册](../doc/user_guide.zh_CN.md)
- [运行时 API 文档](https://docs.rs/qubit-redact)
- [derive API 文档](https://docs.rs/qubit-redact-derive)

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
