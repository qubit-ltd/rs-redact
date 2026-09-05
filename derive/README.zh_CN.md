# qubit-redact-derive

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact-derive.svg?color=blue)](https://crates.io/crates/qubit-redact-derive)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![English Document](https://img.shields.io/badge/Document-English-blue.svg)](README.md)

`qubit-redact-derive` 为 [`qubit-redact`](https://crates.io/crates/qubit-redact)
提供 `#[derive(Redact)]` 过程派生宏。它把经过审查的字段属性转换为策略感知的
`Redact::write_redacted` 实现。derive 不会修改源对象，也不提供可变脱敏 API。

## 安装

```toml
[dependencies]
qubit-redact = { version = "0.6", features = ["derive"] }
qubit-redact-derive = "0.6"
```

## 快速开始

```rust
use qubit_redact::Redactor;
use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Credentials {
    user: String,
    #[redact(level = "secret")]
    password: String,
    #[redact(skip)]
    recovery_code: String,
}

let value = Credentials {
    user: "ada".into(),
    password: "raw-password".into(),
    recovery_code: "never-render".into(),
};
let output = Redactor::standard().redact(&value);
assert!(output.text().as_str().contains("ada"));
assert!(!output.text().as_str().contains("raw-password"));
assert!(!output.text().as_str().contains("never-render"));
```

未标注字段会有意使用普通 `Debug` 输出。字段是否敏感属于下游业务领域知识，derive 宏无法
从字段名或 Rust 类型中可靠推断。现实中普通字段占绝大多数，如果要求它们逐一声明
“不敏感”，只会制造标注噪声，并不会提高分类质量。下游类型必须显式标注敏感字段，并在新增
或修改字段时复查；运行时的 strict policy 和 inspection 不会覆盖这一 derive 决策。

## 字段模式

| 属性 | 行为 |
| --- | --- |
| 无属性 | 使用普通 `Debug` 输出。 |
| `#[redact(level = "low"\|"medium"\|"high"\|"secret")]` | 按指定敏感等级掩码。 |
| `#[redact(skip)]` | 从脱敏输出中省略。 |
| `#[redact(nested)]` | 委托给嵌套值的 `Redact` 实现。 |
| `#[redact(map)]` | 对支持的文本 key Map 按 key 和策略处理。 |
| `#[redact(keyed_by = key)]` | 用兄弟文本 key 对当前字段分类，语义等同一条 Map entry。 |
| `#[redact(json)]` | 对支持的 JSON 文本按 JSON key 递归处理。 |

`#[redact(plain)]`、`#[redact(no_mut)]` 和 `#[redact(require_explicit)]` 不属于当前契约。
宏支持具名、tuple、unit struct，以及 enum 的这些 variant 形态。容器属性
`#[redact(debug)]`、`#[redact(display)]` 和 `#[redact(serde)]` 都必须显式启用；Serde
支持还需要运行时 `serde` feature 和直接声明的 `serde` 依赖。生成的实现会有意在每次格式化
或序列化调用开始时读取当时的 `Redactor::application_default()` 快照，而不是在值创建时固定
策略。因此，替换进程级默认值会影响之后的调用。

`keyed_by` 仅可用于具名字段。被引用的兄弟 key 必须实现 `AsRef<str>`，value 使用与
`level` 相同的递归叶子 capability。standard policy 会放行未知 key；如果未知 payload
key 也必须掩码，应显式配置敏感 key 或使用更严格的策略。

生成代码会解析直接声明的 `qubit-redact` 依赖，也支持 Cargo 重命名。运行时 trait 保持最小化：

```rust
pub trait Redact {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>);
}
```

## 安全边界

只有使用 `Redactor`、生成的格式化实现或生成的序列化实现的边界会受到保护。它不会擦除
源对象，也不能保护无关的日志和序列化路径。`skip` 只省略输出，源字段仍保留在内存中。
未标注字段保持原样是有意划分的责任边界，不是框架遗漏的检查。

策略启用时，生成的 `Debug` 和 `Display` 实现会直接写出运行时产生的保密安全文本，即使
资源限制导致诊断信息不完整，也不强制格式化调用方处理它无法采取行动的完成原因。确实依赖
完整性的程序逻辑应直接调用运行时 API 并检查摘要。

安装 disabled 应用默认值是有意保留的进程级调试逃生口，会让之后生成的 `Debug`、`Display`
和 `Serialize` 调用恢复源值。框架不替调用方授权；环境控制、启用时机及保密后果由调用方
负责。显式创建的运行时 redactor、composer 和 batch 继续持有创建时的策略快照。

需要借用且保持不变的解析 JSON，可使用运行时
`Redactor::redact_json_value(&serde_json::Value)` 或
`Redactor::inspect_json_value(&serde_json::Value)`。

## 延伸阅读

参见[英文用户手册](../doc/user_guide.md)、[中文用户手册](../doc/user_guide.zh_CN.md)、
[API 文档](https://docs.rs/qubit-redact-derive)和
[运行时 crate](https://github.com/qubit-ltd/rs-redact)。

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
