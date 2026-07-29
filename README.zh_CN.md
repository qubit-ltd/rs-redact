# Qubit Redact

[![Rust CI](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact.svg?color=blue)](https://crates.io/crates/qubit-redact)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![English Document](https://img.shields.io/badge/Document-English-blue.svg)](README.md)

Qubit Redact 用于防止秘密经 Rust 日志、`Debug` 输出、进程诊断和 HTTP trace
泄露。无需在各个调用点零散地替换字符串，只需定义不可变策略，并通过有类型、有界且
日志安全的结果完成渲染。

## 为什么选择 Qubit Redact

- 一套策略模型覆盖具名字段、Map、领域对象、进程参数、环境变量和可选 HTTP 诊断。
- 有类型的结果明确区分“字段值已经脱敏”和“文本可以安全写入日志”，让安全边界在代码
  中可见。
- 不合法或已截断的结构化 HTTP 数据会安全关闭，诊断输入和输出预算同时限制资源消耗与
  信息披露。
- 核心没有外部运行时依赖，`serde` 和 `http` 能力均按需启用。

## 快速开始

```toml
[dependencies]
qubit-redact = "0.3"
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
    let user_id = "alpine42";
    let phone_number = "13800138000";
    let credit_card = "4111111111111111";
    let api_key = "sk_live_123";
    let display_name = "Alice\nAdmin";

    assert_eq!(redactor.redact("user_id", user_id).as_str(), "al****42");
    assert_eq!(redactor.redact("phone_number", phone_number).as_str(), "*******0");
    assert_eq!(redactor.redact("credit_card", credit_card).as_str(), "****");
    assert_eq!(redactor.redact("api_key", api_key).as_str(), "<redacted>");
    assert_eq!(redactor.redact("display_name", display_name).as_str(), display_name);
    assert_eq!(api_key, "sk_live_123");
    assert_eq!(
        redactor
            .redact("display_name", display_name)
            .escape_for_log()
            .to_string(),
        "Alice\\nAdmin",
    );
    Ok(())
}
```

原始值仍可供应用逻辑使用，而诊断结果需要显式跨过日志安全边界。每项核心工具的完整
可运行示例请参阅[用户指南](doc/user_guide.zh_CN.md)。

## 如何选择工具

| 诊断输入 | 首选工具 | 安全结果 |
| --- | --- | --- |
| 具名标量或文本 key Map | `Redactor` | `RedactedText`；日志前转为 `LogSafeText` |
| Rust struct 或 enum | `Redact` derive | `Redacted<T>` 视图 |
| 需要逻辑替换的值 | `RedactMut` derive | 已修改对象 |
| 命令行参数 | `ArgvRedactor` | `RedactedArgv` |
| 环境变量 pair | `EnvRedactor` | `RedactedEnvPair` 或 `LogSafeText` |
| URL、form、Header、捕获的 body | `HttpRedactor` | 日志安全 HTTP 结果类型 |

## 设计

Qubit Redact 将职责拆成五层：

- `RedactionPolicy` 是字段规则、允许规则、匹配方式和掩码的不可变快照。
- `Redactor` 使用一份策略处理标量字段值和文本 key 的类 Map 集合。
- 同一 workspace 中的 `qubit-redact-derive` 提供 `Redact` 与 `RedactMut`
  derive，使领域对象的字段边界保持显式；参见其
  [README](https://github.com/qubit-ltd/rs-redact/blob/main/derive/README.zh_CN.md)。
- `ArgvRedactor`、`EnvRedactor` 生成有类型且日志安全的进程诊断结果。
- 可选 `http` 模块处理 URL、form、header 和有界 body。

未知字段会原样通过。因此，本库依靠已知结构和已配置字段名，而不是尝试通用地发现
秘密。默认策略提供保守的预定义规则，builder 可增加业务规则和显式允许决策。

`RedactionPolicy::classify_field` 会把每次决策解释为 `Sensitive`、`Allowed` 或
`Unknown`。匹配字段名直接借用策略中的规则，`sensitivity_for` 也委托给同一套优先级
逻辑。

## Cargo Features

默认 feature 集为空，核心 crate 没有外部运行时依赖。

| Feature | 能力 | 可选依赖 |
| --- | --- | --- |
| `serde` | 序列化显式 opt-in 的脱敏视图 | `serde` |
| `http` | URL、form、header 和有界 body 遮盖 | `form_urlencoded`、`http`、`serde_json`、`url` |

```toml
[dependencies]
# 仅在需要 HTTP 能力的 crate 中启用：
# cargo add qubit-redact --features http
# cargo add http@1.4
qubit-redact = { version = "0.3", features = ["http"] }
qubit-redact-derive = "0.3"
http = "1.4"
```

仅需要无依赖 core 时，改用 `qubit-redact = "0.3"`。

## 标量与 Map

```rust
use std::collections::HashMap;

use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = RedactionPolicy::builder()
        .raise("user_id", Sensitivity::Low)
        .raise("phone_number", Sensitivity::Medium)
        .raise("credit_card", Sensitivity::High)
        .raise("api_key", Sensitivity::Secret)
        .build()?;
    let source = HashMap::from([
        ("user_id".to_owned(), "alpine42".to_owned()),
        ("phone_number".to_owned(), "13800138000".to_owned()),
        ("credit_card".to_owned(), "4111111111111111".to_owned()),
        ("api_key".to_owned(), "sk_live_123".to_owned()),
        ("display_name".to_owned(), "Alice".to_owned()),
    ]);
    let redacted = Redactor::new(policy).redact_map(&source);
    assert_eq!(redacted["user_id"], "al****42");
    assert_eq!(redacted["phone_number"], "*******0");
    assert_eq!(redacted["credit_card"], "****");
    assert_eq!(redacted["api_key"], "<redacted>");
    assert_eq!(redacted["display_name"], "Alice");
    assert_eq!(source["api_key"], "sk_live_123");
    Ok(())
}
```

`redact_map_in_place` 提供对应的原地修改操作。两个 Map 方法都根据 key 分类 value，
保留安全值，并维持具体集合类型。通用 trait 在 runtime crate 不依赖具体集合实现的前提下
覆盖 `HashMap`、`BTreeMap` 和 `indexmap::IndexMap` 等常见集合；key 需实现
`AsRef<str>`，value 需实现相应的 redaction value 契约。像
`serde_json::Map<String, serde_json::Value>` 这样具有异构领域语义的 object map
不在通用实现范围内；应使用领域 newtype 并实现显式脱敏边界。

## 策略配置

```rust
use qubit_redact::{
    FieldNameMatching, MaskPolicy, RedactionPolicy, Redactor, Sensitivity,
};

fn main() {
    let policy = RedactionPolicy::builder()
        .matching(FieldNameMatching::ExactOrTokenSuffix)
        .raise("license_key", Sensitivity::High)
        .allow_exact("public_token")
        .mask(Sensitivity::High, MaskPolicy::fixed("[hidden]"))
        .build()
        .expect("the policy is valid");

    RedactionPolicy::set_global_default(policy.clone())
        .expect("the application installs its default only once");
    let inherited = RedactionPolicy::builder_from_default()
        .build()
        .expect("the default snapshot remains valid");
    assert_eq!(inherited.sensitivity_for("license_key"), Some(Sensitivity::High));

    let redactor = Redactor::new(policy);
    assert_eq!(redactor.redact("LICENSE_KEY", "abcdef").as_str(), "[hidden]");
}
```

`raise` 不会削弱已有规则。只有明确需要替换（包括降级）时才使用
`override_level`。精确允许规则只作用于完整的规范化字段。后缀允许规则还可能允许
`request_public_token` 这样的带前缀字段，披露范围更广；只有审查并接受该风险后才应
使用。

`RedactionPolicy::default()` 读取当前进程级默认策略的快照。
`RedactionPolicy::set_global_default(policy)` 只能成功设置一次；后续调用返回
`GlobalDefaultAlreadySet`，且不会替换已有默认值。`RedactionPolicy::builder()`、
`RedactionPolicyBuilder::new()` 和 `RedactionPolicyBuilder::default()` 都不包含敏感或允许规则。
需要扩展当前保守默认快照时，使用 `RedactionPolicy::builder_from_default()`。
`.load_default()` 会显式将 builder 重置为当前默认快照，并替换此前所有设置（包括已记录的
校验错误）。此前创建的 policy、builder 和 redactor 都不会随之变化。

当安全边界已知某值敏感而与字段名无关时，使用
`Redactor::redact_at(level, value)`。它直接应用指定级别的 mask，允许规则无法暴露该值。

## 领域对象

添加配套的 `qubit-redact-derive` crate 后，可在字段边界声明脱敏语义。没有属性的字段
保持普通值；递归处理和 Map 按 key 分类都必须显式指定。

```rust
use std::collections::HashMap;

use qubit_redact::{Redact as _, RedactionPolicy, Sensitivity};
use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Account {
    id: u64,
    #[redact(level = "secret")]
    password: String,
    #[redact(map)]
    metadata: HashMap<String, String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = RedactionPolicy::builder()
        .raise("api_key", Sensitivity::Secret)
        .build()?;
    let account = Account {
        id: 1,
        password: "raw-password".to_owned(),
        metadata: HashMap::from([
            ("api_key".to_owned(), "raw-key".to_owned()),
        ]),
    };
    let output = format!("{:?}", account.redacted_with(&policy));
    assert!(!output.contains("raw-password"));
    assert!(!output.contains("raw-key"));
    Ok(())
}
```

领域视图的 `Display` 会直接流式写出经过转义、可安全写入日志的内容，不构造完整的中间
表示。如果日志接收端还要求严格的字节预算，可先验证限制，再应用到脱敏视图：

```rust
use qubit_redact::{LogOutputLimit, Redact as _};

# use qubit_redact_derive::Redact;
# #[derive(Redact)]
# struct Event {
#     #[redact(level = "secret")]
#     token: String,
# }
# let event = Event { token: "raw".to_owned() };
let limit = LogOutputLimit::new(128)?;
let output = event.redacted().with_output_limit(limit).to_string();
assert!(output.len() <= limit.max_bytes());
# Ok::<(), Box<dyn std::error::Error>>(())
```

发生截断时，输出以 `<truncated>` 结尾，并且不会截断 UTF-8 字符或生成的控制字符转义
序列。

当视图已持有 `RedactionPolicy` 时，`with_policy_output_limit()` 会使用该策略配置的
`DiagnosticBudget`。

字段类型实现了 `Redact` 时，仍然只有标记 `#[redact(nested)]` 才会递归处理；没有该
属性就绝不隐式遍历。`#[redact(skip)]` 会从脱敏后的 Debug、Display 和 serde 表示中省略
字段，但不会删除或修改原对象字段，`RedactMut` 也不会改它。

`RedactMut` 是独立且显式的逻辑原地脱敏契约。`redact_in_place`、`into_redacted` 和基于
clone 的 `to_redacted` 支持相同的 `level`、`nested`、`map` 字段模式。它不会清零已释放的
分配内存，也不会影响别名、已有副本或借用的后备数据。`to_redacted` 还会短暂产生第二份
原始敏感数据；需要擦除内存时，应采用专门设计的 zeroization 方案。

derive 支持具名、tuple 和 unit struct，也支持 variant 采用这三种字段形态的 enum。
字段属性会保留外层 Rust 形态：tuple 字段保持位置语义，enum 格式化显示当前 variant，
`RedactMut` 也只修改当前 variant 的字段。

```rust
use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Token(#[redact(level = "secret")] String);

#[derive(Redact)]
struct Ready;

#[derive(Redact)]
enum Event {
    Credential(#[redact(level = "secret")] String),
    Ready,
}

assert_eq!(format!("{:?}", Token("raw".into()).redacted()), "Token(\"<redacted>\")");
assert_eq!(format!("{:?}", Ready.redacted()), "Ready");
assert_eq!(
    format!("{:?}", Event::Credential("raw".into()).redacted()),
    "Credential(\"<redacted>\")",
);
assert_eq!(format!("{:?}", Event::Ready.redacted()), "Ready");
```

启用 `serde` 并使用配套 derive crate，再给受支持的 struct 或 enum 添加
`#[redact(serde)]`，即可序列化其脱敏视图。enum 支持 externally tagged、internally
tagged、adjacently tagged 和 untagged 四种标准表示。为避免普通 Serde 自定义绕过脱敏，
derive 只接受保持结构安全的控制项：container 的 `rename`、`rename_all`、
`rename_all_fields`、`tag`、`content`、`untagged`；variant 的 `rename`、
`rename_all`、`skip`、`skip_serializing`；field 的 `rename`、`skip`、
`skip_serializing`、`skip_serializing_if`。启用脱敏序列化后，其他 Serde 控制项会被拒绝。
使用方 crate 必须直接声明 `serde` 依赖（支持重命名依赖），runtime crate 不再转导出它。
`Redacted` 不实现 `Deserialize`。

```rust
use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

#[derive(Redact)]
#[redact(debug, display, serde)]
struct Credentials {
    #[redact(level = "secret")]
    token: String,
    #[redact(skip)]
    internal_note: String,
}

let value = Credentials {
    token: "raw-token".to_owned(),
    internal_note: "not serialized".to_owned(),
};
let json = serde_json::to_string(&value.redacted()).unwrap();
assert!(!json.contains("raw-token"));
assert!(!json.contains("internal_note"));
assert!(!format!("{value:?}").contains("raw-token"));
assert!(!format!("{value}").contains("raw-token"));
```

`#[redact(debug)]` 与 `#[redact(display)]` 让原类型通过进程级默认策略获得安全格式化。
它们不会根据未标注字段的名称推断敏感性。不要同时提供同一 trait 的既有实现；例如
`#[derive(Debug)]` 与 `#[redact(debug)]` 一起使用时，Rust 会正确报告实现冲突。

`redacted()` 会快照进程级默认策略；`redacted_with` 会快照显式策略，所有 nested 和 Map
字段都沿用同一快照。第一版不支持字段级 Map policy；字段需要不同策略边界时，请使用
领域 newtype 并通过 `nested` 处理。

## 进程诊断

`ArgvRedactor::redact_items` 信任调用方提供的敏感等级，不推断命令行语法。
`redact_heuristically` 会识别 `--password value`、`--password=value`、
`-password value`、`NAME=value` 和 `-Dpassword=SECRET` 这类 JVM property；显式标记为
敏感的 `ArgvItem` 始终会被遮盖。它不会推断 `-pSECRET` 这类紧凑 option，也不会解析
shell payload 语法；这些参数可能含有秘密时，调用方必须显式标记。

`EnvRedactor` 处理 UTF-8 pair；任一操作系统组件不是合法 UTF-8 时会安全关闭。结果可
安全显示为 `NAME=VALUE`。
`ArgvRedactor` 和 `EnvRedactor::redact_os_pairs` 也会使用所属
`RedactionPolicy` 的 `DiagnosticBudget`：它们会在检查超大进程输入前停止，并限制最终的
日志安全列表。`MaskingPolicy::mask_opaque` 只返回配置的替换文本，适用于绝不能格式化或
检查原始值的敏感数据。
自定义 `Debug` 实现需要隐藏捕获值时，可使用 `redacted_debug` 固定输出
`<redacted>`；该 wrapper 绝不会调用被包装值自身的 `Debug` 实现。

```rust
use std::ffi::OsStr;

use qubit_redact::{ArgvRedactor, EnvRedactor, argv::ArgvItem};

fn main() {
    let items = [
        ArgvItem::plain(OsStr::new("client")),
        ArgvItem::plain(OsStr::new("--password")),
        ArgvItem::plain(OsStr::new("secret")),
    ];
    let output = ArgvRedactor::default().redact_heuristically(items);
    assert!(!output.to_string().contains("secret"));

    let environment = EnvRedactor::default().redact_pair("PASSWORD", "secret");
    assert_eq!(environment.to_string(), "PASSWORD=<redacted>");

    let captured_bytes = b"secret output";
    assert_eq!(
        format!("{:?}", qubit_redact::redacted_debug(captured_bytes)),
        "<redacted>",
    );

    let log_safe = qubit_redact::Redactor::default()
        .redact("message", "line one\nline two")
        .escape_for_log();
    assert_eq!(log_safe.to_string(), "line one\\nline two");
}
```

`RedactedText` 刻意不实现 `Display`：值遮盖和日志转义是两种不同保证。把标量结果写入
纯文本日志前，必须显式调用 `escape_for_log()`。argv 和 env 的结果类型已经跨过该边界，
可安全地使用 `Display`。

## HTTP 脱敏

通过 `cargo add qubit-redact --features http` 启用 `http`，并通过
`cargo add http@1.4` 添加示例直接使用的 `http` 依赖（或使用上面的等价 Cargo.toml
配置）。HTTP 核心类型的职责如下：

| 类型 | 职责 |
| --- | --- |
| `HttpRedactionPolicy` | 不可变的按上下文策略快照，包含 header、query/form、body 字段规则、行为选择和预算。 |
| `HttpRedactionPolicyBuilder` | `new()` 和 `Default` 都不包含字段规则，但保留安全行为和预算。使用 `HttpRedactionPolicy::builder_from_default()` 扩展保守 HTTP 快照；`.load_default()` 会显式重置此前全部 builder 状态。 |
| `HttpRedactor` | 使用一份不可变 HTTP 策略处理 URL、form、header 和调用方提供的 body capture。 |
| `BodyCapture` | 带有真实完整性元数据的借用字节；用 `complete`、`prefix` 或截断构造函数说明实际可用输入。 |
| `BodyBudget` | 限制参与 body 处理的字节数，以及最终 body 文本的渲染长度。 |
| `BodyRedaction` | 有界、日志安全的 body 结果；其 `Display` 不提供原始 body 逃生口。 |
| `BodyRedactionStatus` | 标明结果是空、结构化成功、由策略放行、安全关闭，还是二进制摘要。 |
| `BodyRedactionReason` | 解释安全关闭原因，例如结构化输入不合法/已截断、媒体类型不支持或不透明文本。 |
| `DiagnosticBudget` | 单独限制 URL、form、header 和含 URL 文本的诊断。 |

`DiagnosticBudget` 默认输入上限为 16 KiB、输出上限为 64 KiB。输入超限时只返回
`<redacted: diagnostic limit exceeded>`，不会保留任何源前缀。同一预算也限制聚合 argv 和
environment 诊断。`HttpRedactionPolicy::default()` 和 `HttpRedactor::default()` 仍使用
保守的 HTTP 默认策略。

不合法或已截断的结构化 body 会安全关闭。不透明文本、无 key 的 JSON 标量、文件
part、匿名 multipart part 和 URL path 默认采用保守策略。HTTP 结果类型只暴露日志
安全文本，不提供原始 body 逃生口。

```rust
use http::HeaderValue;
use qubit_redact::http::{
    BodyCapture,
    BodyRedaction,
    DiagnosticBudget,
    HttpRedactionPolicy,
    HttpRedactor,
};

fn main() {
    let diagnostics = DiagnosticBudget::new(8 * 1024, 32 * 1024)
        .expect("诊断预算合法");
    let policy = HttpRedactionPolicy::builder_from_default()
        .diagnostic_budget(diagnostics)
        .build()
        .expect("HTTP 策略合法");
    let body = br#"{"password":"secret","mode":"debug"}"#;
    let content_type = HeaderValue::from_static("application/json");
    let result: BodyRedaction = HttpRedactor::new(policy)
        .redact_body(BodyCapture::complete(body), Some(&content_type));
    let display_text = format!("{result}");
    assert!(!display_text.contains("secret"));
}
```

HTTP 遮盖只接受调用方提供的有界 capture，不会自行读取或缓存网络 body。
`BodyRedaction` 的 `Display` 实现就是安全日志边界，并且会保持配置的输出预算。

`TextBodyPolicy::PassThrough`、`UnkeyedJsonValuePolicy::PassThrough` 和
`UrlPathPolicy::Preserve` 都是显式诊断 opt-in。只有应用已经接受相应信息披露风险时才
应选择它们。

## 安全边界

- 字段名会被规范化，可选择精确或 token 后缀匹配。
- 允许规则会有意胜出并可能暴露数据，应把它们作为安全策略审查。
- 本库不会发现保存在未知字段名下的秘密。
- 可变脱敏只替换逻辑值；它不保证擦除已释放的分配内存、别名、副本或借用的后备数据。
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

仓库地址：[https://github.com/qubit-ltd/rs-redact](https://github.com/qubit-ltd/rs-redact)
