# Qubit Redact 用户手册

Qubit Redact 是一个策略驱动的 Rust 脱敏库，用于防止敏感值经诊断信息泄露：
结构化字段和 Map、领域对象、进程参数、环境变量，以及可选的 HTTP 数据都在其覆盖范围内。

## 它解决什么问题

秘密通常不是从认证代码泄露，而是从错误日志、调试输出和序列化诊断对象泄露。
在每个日志调用点做字符串替换容易遗漏，也难以审查。Qubit Redact 用不可变
`RedactionPolicy` 集中定义“什么可以展示、什么必须遮盖”。

下面的完整程序保留原始秘密，同时遮盖诊断值。

```toml
[dependencies]
qubit-redact = "0.3"
```

```rust
use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = RedactionPolicy::empty_builder()
        .raise("api_key", Sensitivity::Secret)
        .build()?;
    let raw = "sk_live_123";
    let diagnostic = Redactor::new(policy).redact("api_key", raw);

    assert_eq!(raw, "sk_live_123");
    assert_eq!(diagnostic.as_str(), "<redacted>");
    Ok(())
}
```

## 安装与示例运行方式

包名是 `qubit-redact`，Rust 导入路径是 `qubit_redact`。默认 feature 没有运行时
依赖；领域对象使用 derive crate，脱敏序列化启用 `serde`，HTTP 诊断启用 `http`。
本手册每个 Rust 代码块都是完整的 `main.rs`：使用该节给出的依赖并运行 `cargo run`。

```toml
[dependencies]
qubit-redact = { version = "0.3", features = ["serde", "http"] }
qubit-redact-derive = "0.3"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
http = "1.4"
```

## 核心概念

`RedactionPolicy` 是字段规则、匹配方式、掩码和诊断预算的不可变快照。字段决策分为：
**Sensitive**（遮盖）、显式例外的 **Allowed**（允许展示）和 **Unknown**（原样保留）。
`Redactor` 始终使用同一份快照。

`RedactedText` 只表示“已按字段规则处理”，它故意不实现 `Display`。写入纯文本日志前，
必须调用 `escape_for_log()` 得到可安全显示的 `LogSafeText`。

## 1. 用 `RedactionPolicy` 配置规则

`RedactionPolicy::builder()` 从当前进程默认快照开始；`empty_builder()` 只保留你
显式添加的规则。`raise` 不会降低既有等级；需要有意替换时使用
`override_level`。精确允许规则范围窄；后缀允许规则可能放行带前缀字段，需安全审查。

```rust
use qubit_redact::{
    FieldNameMatching, MaskPolicy, RedactionPolicy, Redactor, Sensitivity,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = RedactionPolicy::empty_builder()
        .matching(FieldNameMatching::ExactOrTokenSuffix)
        .raise("license_key", Sensitivity::High)
        .allow_exact("public_token")
        .mask(Sensitivity::High, MaskPolicy::fixed("[hidden]"))
        .build()?;
    let redactor = Redactor::new(policy);

    assert_eq!(redactor.redact("LICENSE_KEY", "abc").as_str(), "[hidden]");
    assert_eq!(redactor.redact("public_token", "visible").as_str(), "visible");
    Ok(())
}
```

`RedactionPolicy::set_global_default` 只应在应用初始化时调用，且每个进程只能成功一次。
测试或多个安全边界应传递显式策略快照。

## 2. 用 `Redactor` 处理标量和 Map

`redact(field, value)` 是基本操作。`redact_map` 返回保持原集合类型的副本，
`redact_map_in_place` 原地替换敏感值。支持文本 key 的 `HashMap`、`BTreeMap` 和
`indexmap::IndexMap`。

```rust
use std::collections::HashMap;
use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = RedactionPolicy::empty_builder()
        .raise("password", Sensitivity::Secret)
        .build()?;
    let source = HashMap::from([
        ("password".to_owned(), "raw-password".to_owned()),
        ("display_name".to_owned(), "Ada".to_owned()),
    ]);

    let copy = Redactor::new(policy).redact_map(&source);
    assert_eq!(copy["password"], "<redacted>");
    assert_eq!(copy["display_name"], "Ada");
    assert_eq!(source["password"], "raw-password");
    Ok(())
}
```

不要将 `serde_json::Map<String, serde_json::Value>` 这类异构领域对象当作普通字符串
Map；应通过领域类型定义明确的替换语义。

## 3. 将脱敏文本安全写入日志

脱敏与日志安全是两层保证：即使字段允许展示，换行符或 Unicode 控制字符仍可改变日志
结构。`escape_for_log()` 返回实现 `Display` 的 `LogSafeText`。`LogOutputLimit` 对最终
输出施加字节上限，并以 `<truncated>` 截断，且不会切断 UTF-8 或转义序列。

```rust
use qubit_redact::{LogOutputLimit, Redactor};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let safe = Redactor::default()
        .redact("message", "first line\nsecond line")
        .escape_for_log();
    assert_eq!(safe.to_string(), "first line\\nsecond line");

    let limit = LogOutputLimit::new(16)?;
    let bounded = safe.with_output_limit(limit).to_string();
    assert!(bounded.len() <= limit.max_bytes());
    Ok(())
}
```

在自定义 `Debug` 实现中，如捕获值必须固定显示为 `<redacted>`，请使用
`redacted_debug(value)`；它不会调用被包装值自己的 `Debug` 实现。

## 4. 用 `Redact` 和 `RedactMut` 处理领域对象

添加 `qubit-redact-derive` 后，可在字段边界声明语义：`level` 遮盖字段，`nested`
递归，`map` 按 key 处理 Map 值，`skip` 从脱敏表示中省略字段。

```toml
[dependencies]
qubit-redact = "0.3"
qubit-redact-derive = "0.3"
```

```rust
use qubit_redact::{Redact as _, RedactMut as _};
use qubit_redact_derive::{Redact, RedactMut};

#[derive(Clone, Redact, RedactMut)]
struct Credentials {
    user: String,
    #[redact(level = "secret")]
    password: String,
    #[redact(skip)]
    internal_note: String,
}

fn main() {
    let credentials = Credentials {
        user: "ada".to_owned(),
        password: "raw-password".to_owned(),
        internal_note: "not logged".to_owned(),
    };
    assert!(!format!("{:?}", credentials.redacted()).contains("raw-password"));

    let mut mutable = credentials.clone();
    mutable.redact_in_place();
    assert_eq!(mutable.password, "<redacted>");
    assert_eq!(mutable.internal_note, "not logged");
}
```

`RedactMut` 仅做逻辑替换，不会擦除已释放的内存、别名、副本或借用后备存储；需要内存
擦除时请使用专门的 zeroization 方案。

### 使用 Serde 序列化脱敏视图

序列化必须显式 opt-in：启用 `serde` feature，在使用方直接声明 `serde`，并添加
`#[redact(serde)]`。`Redacted` 不实现 `Deserialize`。

```toml
[dependencies]
qubit-redact = { version = "0.3", features = ["serde"] }
qubit-redact-derive = "0.3"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

```rust
use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

#[derive(Redact)]
#[redact(serde)]
struct LoginEvent {
    account: String,
    #[redact(level = "secret")]
    token: String,
    #[redact(skip)]
    internal_note: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let event = LoginEvent {
        account: "ada".to_owned(),
        token: "raw-token".to_owned(),
        internal_note: "operator-only".to_owned(),
    };
    let json = serde_json::to_string(&event.redacted())?;
    assert!(!json.contains("raw-token"));
    assert!(!json.contains("operator-only"));
    Ok(())
}
```

## 5. 用 `ArgvRedactor` 处理命令行参数

`redact_items` 信任 `ArgvItem` 提供的敏感等级；`redact_heuristically` 还识别
`--password value`、`--password=value`、`-password value`、`NAME=value` 和
`-Dpassword=value`。它不会推断紧凑的 `-pSECRET` 或 shell payload，必须显式标记。

```rust
use std::ffi::OsStr;
use qubit_redact::{ArgvRedactor, Sensitivity, argv::ArgvItem};

fn main() {
    let items = [
        ArgvItem::plain(OsStr::new("client")),
        ArgvItem::plain(OsStr::new("--password")),
        ArgvItem::plain(OsStr::new("raw-password")),
        ArgvItem::sensitive(OsStr::new("raw-api-key"), Sensitivity::Secret),
    ];
    let output = ArgvRedactor::default().redact_heuristically(items).to_string();
    assert!(!output.contains("raw-password"));
    assert!(!output.contains("raw-api-key"));
}
```

返回的 `RedactedArgv` 可安全显示；输入和输出受策略中的 `DiagnosticBudget` 限制。

## 6. 用 `EnvRedactor` 处理环境变量

`EnvRedactor` 通过变量名分类其值，返回日志安全的 `NAME=VALUE`。`redact_os_pair`
接受 `OsStr`，遇到非 UTF-8 输入会安全关闭并使用不透明掩码。

```rust
use qubit_redact::EnvRedactor;

fn main() {
    let redactor = EnvRedactor::default();
    let password = redactor.redact_pair("PASSWORD", "raw-password");
    let assignment = redactor.redact_assignment("API_TOKEN=raw-token");

    assert_eq!(password.to_string(), "PASSWORD=<redacted>");
    assert!(!assignment.to_string().contains("raw-token"));
}
```

渲染进程变量列表时使用 `redact_os_pairs`：它在整个列表中共享输入预算，超出时用截断
标记停止，而不会继续读取原始数据。

## 7. 用 `HttpRedactor` 处理 HTTP 诊断

可选 `http` feature 提供不可变 `HttpRedactionPolicy`，分别处理 Header、query/form 和
结构化 body。`BodyCapture` 明确标记输入是否完整或源数据已截断；库不会读取网络流，也
没有暴露原始 body 的逃生接口。

```toml
[dependencies]
qubit-redact = { version = "0.3", features = ["http"] }
http = "1.4"
```

```rust
use http::{HeaderMap, HeaderValue};
use qubit_redact::Sensitivity;
use qubit_redact::http::{BodyCapture, HttpRedactionPolicy, HttpRedactor};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = HttpRedactionPolicy::builder()
        .raise_body("password", Sensitivity::Secret)
        .raise_query("api_key", Sensitivity::Secret)
        .build()?;
    let redactor = HttpRedactor::new(policy);

    let url = redactor.redact_url_str(
        "https://api.example.test/login?api_key=raw-key&mode=debug",
    );
    assert!(!url.to_string().contains("raw-key"));

    let mut headers = HeaderMap::new();
    headers.insert("authorization", HeaderValue::from_static("Bearer raw-token"));
    assert!(!redactor.redact_headers(&headers).to_string().contains("raw-token"));

    let content_type = HeaderValue::from_static("application/json");
    let body = redactor.redact_body(
        BodyCapture::complete(br#"{"password":"raw-password","mode":"debug"}"#),
        Some(&content_type),
    );
    assert!(!body.to_string().contains("raw-password"));
    Ok(())
}
```

`HttpRedactionPolicyBuilder` 提供 `raise_header`、`raise_query` 和 `raise_body` 等
上下文规则。`BodyBudget` 限制 body 解析和输出；`DiagnosticBudget` 单独限制 URL、
form、Header 和含 URL 的文本。无效或截断的结构化输入会安全关闭。

## 如何选择工具

| 诊断输入 | 首选工具 | 安全结果 |
| --- | --- | --- |
| 具名标量或文本 key Map | `Redactor` | `RedactedText`；日志前转为 `LogSafeText` |
| Rust struct 或 enum | `Redact` derive | `Redacted<T>` 视图 |
| 需要逻辑替换的值 | `RedactMut` derive | 已修改对象 |
| 命令行参数 | `ArgvRedactor` | `RedactedArgv` |
| 环境变量 pair | `EnvRedactor` | `RedactedEnvPair` 或 `LogSafeText` |
| URL、form、Header、捕获的 body | `HttpRedactor` | 日志安全 HTTP 结果类型 |

## 安全边界与验证

- 未知字段原样通过；为所有可控字段名配置规则。本库不是通用秘密探测器。
- 允许规则会有意披露数据且优先级更高；优先使用精确允许规则。
- 不要直接格式化 `RedactedText`；先调用 `escape_for_log()`。
- 不要把 `RedactMut` 当作内存擦除机制。
- 只有接受披露风险后，才启用 `TextBodyPolicy::PassThrough`、
  `UnkeyedJsonValuePolicy::PassThrough` 或 `UrlPathPolicy::Preserve`。

发布影响行为或示例的变更前，运行完整 feature 集：

```bash
cargo test --all-features
./ci-check.sh
```

