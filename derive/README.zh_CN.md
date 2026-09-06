# qubit-redact-derive

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact-derive.svg?color=blue)](https://crates.io/crates/qubit-redact-derive)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![English Document](https://img.shields.io/badge/Document-English-blue.svg)](README.md)

`qubit-redact-derive` 为领域对象生成借用脱敏能力，为标量值对象生成 `RedactScalar`。
常规字段由业务开发者决定敏感性，复杂对象使用 `nested` 委托内部规则。

## 安装

推荐通过 runtime 重导出使用宏，无需再单独声明 derive crate：

```toml
[dependencies]
qubit-redact = { version = "0.6", features = ["derive", "serde", "json"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

## 快速开始

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

## 字段与容器属性

| 字段属性 | 作用与类型要求 |
| --- | --- |
| 无属性 | 文本使用普通 `Debug`；结构化视图序列化需要 `#[redact(serde)]`。 |
| `level = "low"/"medium"/"high"/"secret"` | 对各叶子应用最终等级；支持基本标量、`RedactScalar` 和支持的递归容器。 |
| `level = "...", display` | 显式按 `Display` 文本处理，不要求该类型实现 `Debug` 或普通 `Serialize`。 |
| `skip` | 启用时省略；disabled 恢复字段。 |
| `nested` | 委托 `Redact`；结构化输出使用嵌套值生成的视图投影。 |
| `map` | 支持 key 为 `String`、`&str`、`Cow<str>` 的 `HashMap`/`BTreeMap`，以及外层 `Option`；value 需具备等级能力，放行文本还需 `Debug`。 |
| `map_key_level = "..."` | 固定每个 key 的等级，value 保持普通输出。 |
| `map_key_level = "...", map_value_level = "..."` | 分别固定 key、value 等级。 |
| `keyed_by = key` | 按实现 `AsRef<str>` 的兄弟 key 分类，仅用于具名字段；value 需具备等级能力和 `Debug`。 |
| `json` | 支持 JSON `String`/`str`/`Cow<str>`、已解析 `serde_json::Value`、引用和 `Option`；需要 `json` feature。 |

容器属性包括 `debug`、`display`、`serde`、`transparent` 和 `crate = path`。
`serde` 为 `redact_view()` 生成结构化脱敏能力，并接管普通 `Serialize` 输出。
它需要 runtime 的 `serde` feature 和直接声明的 Serde 依赖。
`transparent` 要求恰好一个字段，委托该字段的表示，本身不声明标量能力。
`debug` 不应与普通 `Debug` 派生同时使用，`serde` 不应与普通 `Serialize` 派生同时使用。

## 标量值对象

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

`RedactScalar` 要求恰好一个标量字段，支持具名和 tuple struct、多层标量包装。
它不生成普通 Debug、Display 或 Serialize，也不设置敏感等级；容器不能作为其内部标量。
第三方类型采用 `#[redact(level = "secret", display)]`。

## 延伸阅读

参见[中文用户手册](../doc/user_guide.zh_CN.md)、[英文用户手册](../doc/user_guide.md)
与[运行时 README](../README.zh_CN.md)，了解预算、Serde 兼容性、快照和 disabled 行为。

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
