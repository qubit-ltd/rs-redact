# rs-sanitize 0.3 发布前收口设计

## 目标

在 `qubit-sanitize 0.3.0` 发布前一次性收口审查中发现的 API、默认安全语义、
HTTP body 结果建模、下游版本一致性和代码组织问题。直接下游同步迁移到最终 API，
避免在 0.3 发布后再承担一次不必要的破坏性升级。

本次设计基于以下事实：

- registry 中的 `qubit-sanitize` 仍为 `0.2.2`，本地 `0.3.0` 尚处于发布准备阶段；
- 本地 `qubit-command 0.4.2` 已与 registry 中同版本的依赖图不同，不能继续使用
  相同发布版本；
- `rs-http 0.10.0` 直接使用本地 `qubit-sanitize 0.3`，可以在发布前同步迁移；
- `rs-platform` 和 `rs-llmsdk-core` 当前没有依赖 `qubit-sanitize`，不在本次代码
  修改范围内。

## 范围

本次修改覆盖：

- `rs-sanitize`：feature matrix、公开 policy API、HTTP body 结果、URL 结构字段等级、
  安全 Debug wrapper、默认字段、multipart 歧义处理、测试、文档和内部文件组织；
- `rs-http`：迁移结构化 body 结果和私有化 policy API，删除展示字符串解析；
- `rs-command`：版本升级和安全 `CommandOutput::Debug`；
- `rs-value`：将 `qubit-datatype` 固定为同仓库相对路径依赖，避免下游同时解析本地与
  registry 的同版本类型；
- `rs-config`：验证其 `qubit-datatype`/`qubit-value` 本地依赖图保持单一类型身份；
- `rs-mime`：版本升级、切换本地 `qubit-command 0.5`、更新锁文件；
- `rs-magika`：更新经 `rs-mime` 形成的锁文件依赖图。

不修改存在用户未提交变更的 `rs-llmsdk-core`，也不修改尚未形成 sanitizer 依赖的
`rs-platform`。

## 版本策略

- `qubit-sanitize` 保持 `0.3.0`。本次是在首次 0.3 发布前完成 API 收口；
- `qubit-http` 保持尚未发布的 `0.10.0`，直接迁移最终 0.3 API；
- `qubit-command` 从 `0.4.2` 升到 `0.5.0`。它公开重导出
  `qubit_sanitize::SensitivityLevel`，依赖类型身份变化属于 0.x 下的破坏性变化；
- `qubit-value` 保持 `0.10.0`，仅补齐已发布版本约束旁的本地 path；
- `qubit-config` 保持 `0.14.0`，其现有本地 path 依赖不改变；
- `qubit-mime` 从 `0.9.0` 升到 `0.9.1`，其公共 API 不暴露 `qubit-command` 类型，
  依赖升级按 patch 版本发布；
- `qubit-magika` 保持 `0.8.0`，只更新锁文件中经本地 `qubit-mime` 形成的依赖图。

发布准备期间使用相对路径依赖：

```toml
# rs-command
qubit-sanitize = {
    version = "0.3",
    path = "../rs-sanitize",
    default-features = false,
}

# rs-http
qubit-sanitize = {
    version = "0.3",
    path = "../rs-sanitize",
    default-features = false,
    features = ["web", "http"],
}

# rs-mime
qubit-command = { version = "0.5", path = "../rs-command" }

# rs-value
qubit-datatype = {
    version = "0.6",
    path = "../rs-datatype",
    default-features = false,
}
```

`rs-mime` 和 `rs-magika` 的锁文件最终都必须解析到本地 `qubit-command 0.5.0` 与
`qubit-sanitize 0.3.0`，不得再包含 `qubit-sanitize 0.2.2`。

各 crate 的 README、用户指南和依赖示例同步使用上述版本，不保留指向旧
`qubit-command 0.4` 或旧 sanitizer API 的示例。

## Feature matrix 修复

`core` 已不再是 Cargo feature。core 类型、`ArgvSanitizer` 和 `EnvSanitizer` 始终
编译。`.rs-ci-cargo-matrix.json` 使用以下组合：

```text
core: --no-default-features
web:  --no-default-features --features web
http: --no-default-features --features http
all:  --all-features
```

matrix 不得再传入不存在的 `core` feature。README 和 Rustdoc 中的“core”可以继续
表示架构层，但不得把它描述为 Cargo feature。

## HTTP body 结构化结果

### 公开类型

新增三个 HTTP feature 下的公开类型：

```rust
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyRedactionReason {
    InvalidContentType,
    InvalidJson,
    InvalidOrTruncatedJson,
    InvalidNdjson,
    InvalidOrTruncatedNdjson,
    InvalidMultipart,
    TruncatedMultipart,
    UnsupportedMediaType,
    OpaqueText,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodySanitizationStatus {
    Empty,
    Sanitized,
    Redacted(BodyRedactionReason),
    Binary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodySanitization {
    content: String,
    status: BodySanitizationStatus,
    captured_len: usize,
    source_len: usize,
}
```

`content` 是不带标准截断后缀的诊断内容。类型提供：

```rust
pub fn content(&self) -> &str;
pub fn into_content(self) -> String;
pub const fn status(&self) -> BodySanitizationStatus;
pub const fn captured_len(&self) -> usize;
pub const fn source_len(&self) -> usize;
pub const fn truncated_bytes(&self) -> usize;
pub const fn is_truncated(&self) -> bool;
pub fn rendered(&self) -> String;
pub fn into_rendered(self) -> String;
```

`Display` 与 `rendered` 使用当前标准格式
`...<truncated N bytes>`；调用方若有自己的展示契约，使用 `content` 和
`truncated_bytes`，不再解析标准字符串。

### Sanitizer API

以下方法改为返回 `BodySanitization`：

```rust
pub fn sanitize_body(...) -> BodySanitization;
pub fn sanitize_body_preview(...) -> BodySanitization;
```

这是有意的发布前破坏性收口。调用方需要字符串时调用 `to_string()` 或
`into_rendered()`。不保留同名 String 返回 API，避免同时维护两套主契约。

完整 body 的 `captured_len` 等于 `source_len`。preview 把小于 prefix 长度的
`source_len` 规范为 prefix 长度。截断字节数使用饱和减法。

解析成功的 JSON、NDJSON、form、multipart 和允许透传的 text 使用
`Sanitized`。无法安全解析或不受支持的文本使用带原因的 `Redacted`；二进制路径使用
`Binary`；空完整 body 和空 preview 使用 `Empty`，但空 preview 仍可携带非零截断
字节数。

### rs-http 迁移

`rs-sanitize::HttpBodySanitizer` 的通用默认继续是 `TextBodyPolicy::Redact`。
`rs-http::LogSanitizer` 的 body 记录由调用方日志策略显式启用，因此构造内部 sanitizer
时明确选择 `TextBodyPolicy::PassThrough`，保持既有 HTTP 日志契约；结构化字段仍按
policy 脱敏。

`rs-http::LogSanitizer::sanitize_body_preview` 直接读取 `BodySanitization`：

- 普通请求/响应日志使用 `into_rendered()`；
- error-response 使用 `into_content()` 和 `truncated_bytes()` 生成自己的历史后缀；
- 删除 `normalize_error_truncation_suffix` 对
  `...<truncated N bytes>` 的 `strip_suffix` 解析。

现有 marker 文案继续由 `rs-sanitize` 的 `Display` 保持，结构化元数据成为跨 crate
集成契约。

## Policy API 收口

### MaskPolicies

`MaskPolicies` 的 `low`、`medium`、`high`、`secret` 字段改为私有。保留
`for_level`，新增：

```rust
pub fn new(
    low: MaskPolicy,
    medium: MaskPolicy,
    high: MaskPolicy,
    secret: MaskPolicy,
) -> Self;
pub fn for_level_mut(&mut self, level: SensitivityLevel) -> &mut MaskPolicy;
pub fn set(&mut self, level: SensitivityLevel, policy: MaskPolicy);
pub fn with_policy(self, level: SensitivityLevel, policy: MaskPolicy) -> Self;
```

`SensitivityLevel` 的文档明确最强等级顺序为
`Low < Medium < High < Secret`；`merge_strongest` 继续依赖该顺序。

### FieldSanitizePolicy

`sensitive_fields` 和 `mask_policies` 改为私有。公开 API 为：

```rust
pub const fn new(
    sensitive_fields: SensitiveFields,
    mask_policies: MaskPolicies,
) -> Self;
pub const fn sensitive_fields(&self) -> &SensitiveFields;
pub fn sensitive_fields_mut(&mut self) -> &mut SensitiveFields;
pub const fn mask_policies(&self) -> &MaskPolicies;
pub fn mask_policies_mut(&mut self) -> &mut MaskPolicies;
pub fn with_sensitive_fields(self, fields: SensitiveFields) -> Self;
pub fn with_mask_policies(self, policies: MaskPolicies) -> Self;
```

直接下游全部迁移到构造器和方法，不再使用 struct literal。

### 强等级合并与显式覆盖

`SensitiveFields::insert` 和 `extend` 保留类似 map 的覆盖语义，但 Rustdoc 必须明确：
已存在的规范化字段会被新等级替换，可能降低敏感等级。新增：

```rust
pub fn insert_strongest(&mut self, field: &str, level: SensitivityLevel);
pub fn extend_strongest<I, S>(&mut self, fields: I, level: SensitivityLevel)
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>;
```

`FieldSanitizer::insert_sensitive_field` 和 `extend_sensitive_fields` 改用 strongest 语义，
使名称为“添加”的 facade 默认不能降低内建等级。需要显式覆盖时使用新增方法：

```rust
pub fn set_sensitive_field_level(
    &mut self,
    field: &str,
    level: SensitivityLevel,
);
```

### rs-http LogSanitizePolicy

三个 `SensitiveFields` 字段改为私有，避免把依赖类型暴露为可直接构造的公共字段。
`qubit-http` 从 crate root 重导出 `qubit_sanitize::SensitivityLevel`，调用方不必自行
添加并猜测兼容的 `qubit-sanitize` 版本。

公开领域方法包括：

```rust
pub fn empty() -> Self;
pub fn insert_sensitive_header(&mut self, name: &str, level: SensitivityLevel);
pub fn insert_sensitive_query_param(&mut self, name: &str, level: SensitivityLevel);
pub fn insert_sensitive_body_field(&mut self, name: &str, level: SensitivityLevel);
pub fn extend_sensitive_headers<I, S>(&mut self, names: I, level: SensitivityLevel);
pub fn extend_sensitive_query_params<I, S>(&mut self, names: I, level: SensitivityLevel);
pub fn extend_sensitive_body_fields<I, S>(&mut self, names: I, level: SensitivityLevel);
pub fn set_sensitive_header_level(&mut self, name: &str, level: SensitivityLevel);
pub fn set_sensitive_query_param_level(&mut self, name: &str, level: SensitivityLevel);
pub fn set_sensitive_body_field_level(&mut self, name: &str, level: SensitivityLevel);
pub fn remove_sensitive_header(&mut self, name: &str) -> Option<SensitivityLevel>;
pub fn remove_sensitive_query_param(&mut self, name: &str) -> Option<SensitivityLevel>;
pub fn remove_sensitive_body_field(&mut self, name: &str) -> Option<SensitivityLevel>;
pub fn sensitivity_for_header(&self, name: &str) -> Option<SensitivityLevel>;
pub fn sensitivity_for_query_param(&self, name: &str) -> Option<SensitivityLevel>;
pub fn sensitivity_for_body_field(&self, name: &str) -> Option<SensitivityLevel>;
```

`insert`、`extend` 方法使用 strongest 语义；`set` 方法是明确允许降低等级的覆盖
入口。`LogSanitizer` 和 options 配置通过 `pub(crate)` 只读访问器读取三组字段。
`empty()` 是明确的 custom-only 构造器；Debug sanitization 仍会把内建默认值
strongest 合并回来，TRACE 则严格使用调用方 policy。该安全差异必须写入 Rustdoc。

## URL 结构字段等级

`UrlSanitizer` 不再使用一个固定等级处理所有结构字段：

- username：`High`；
- password：`Secret`；
- fragment：`High`；
- query：继续按 query 参数名解析等级。

URL path 仍原样保留，调用方继续负责厂商或业务协议定义的敏感 path。测试必须自定义
High 为保留前后缀、Secret 为固定 redaction，并证明 password 不暴露字符。

## 安全 Debug wrapper 与 rs-command

### RedactedDebug

core 新增借用式 wrapper：

```rust
pub struct RedactedDebug<'a, T: ?Sized> {
    value: &'a T,
}

pub const fn redacted_debug<T: ?Sized>(value: &T) -> RedactedDebug<'_, T>;
```

`Debug` 始终输出 `<redacted>`，绝不调用被包装值的 `Debug`。本次不增加可配置 marker、
拥有型敏感值或任意文本扫描器，避免把存储和授权语义引入诊断 crate。

### CommandOutput

`CommandOutput` 取消派生 `Debug`，改为手写实现。输出状态码、执行时间、stdout/stderr
长度和截断状态；stdout/stderr 内容字段使用 `redacted_debug`，不得输出捕获字节。
`CommandError` 可继续派生 `Debug`，因为嵌套 `CommandOutput` 已具有安全实现。

测试使用可搜索的 secret bytes 构造 timeout/unexpected-exit 错误，断言 Debug 不包含
原值且包含长度和截断元数据。原始输出访问器和 `Display` 行为不变。

## 默认字段 preset

`SensitiveFieldPreset::Credentials` 增加：

```text
security_key -> Secret
```

这是由 `rs-platform::WithSecurityKey` 提供的真实下游命名。默认字段仍只是 starter
set，不加入未经下游证据支持的大型 provider 词典。

## Multipart 歧义处理

multipart sanitizer 对解析歧义 fail closed：

- 同一 part 出现重复 `Content-Disposition` 时，整个 multipart body redaction；
- 同一 part 出现重复 `Content-Type` 时，整个 multipart body redaction；
- `Content-Disposition` 中重复 `name`、`filename` 或 `filename*` 参数时，整个 body
  redaction；
- 缺失可选参数仍沿用现有安全路径，不把“缺失”和“重复”混为一谈；
- malformed quoting、CR/LF 和非法 boundary 的既有 redaction 行为不变。

内部 parameter parser 改为区分 `Absent`、`Value` 和 `Invalid/Ambiguous`。错误仅在
crate 内传播，不增加公开错误类型；HTTP body API 仍返回带
`BodyRedactionReason::InvalidMultipart` 的结果。

## 内部文件与测试组织

新增 `src/adapter/http/internal/`：

```text
internal/
  mod.rs
  body_input_kind.rs
  multipart_delimiter.rs
  header_parameter.rs
```

私有 `BodyInputKind`、`MultipartDelimiter` 和 header parameter 解析状态各自独立成
文件。公开 API 文件继续位于现有 adapter 路径。

以下测试文件按源码公开类型名重命名，并更新 `tests/adapter/mod.rs`：

```text
argv_tests.rs            -> argv_sanitizer_tests.rs
env_tests.rs             -> env_sanitizer_tests.rs
form_urlencoded_tests.rs -> form_url_encoded_sanitizer_tests.rs
url_tests.rs             -> url_sanitizer_tests.rs
```

仅给简单 getter、setter、常量方法和纯转发函数增加 `#[inline]`。解析、分配、循环和
分支较多的方法不标注。

项目现有 Rustdoc 统一使用 `# Parameters`。本次继续沿用该标题，不批量替换成
`# Arguments`；两者对 Rustdoc 都只是 Markdown 标题，保持仓库一致性优先。

## 测试策略

功能修改严格执行测试先行，每个红绿循环只验证一种行为：

1. `BodySanitization` accessor、状态、reason、截断与 Display；
2. `rs-http` 不再依赖 marker 解析；
3. policy 私有化后的构造、读写与 strongest facade；
4. URL password 使用 Secret；
5. `RedactedDebug` 不调用或输出内部 Debug，`CommandOutput::Debug` 不泄漏字节；
6. `security_key` 默认命中 Secret；
7. multipart 重复 header/参数整体 redaction。

每项先编写最小失败测试并运行确认失败原因，再实现最小代码并运行相关测试。Cargo
版本、feature matrix、锁文件、文档和纯文件重命名属于配置或机械修改，不为其制造
无意义的失败单元测试；通过 feature 命令、依赖图、Rustdoc 和完整测试验证。

测试继续全部放在 `tests/`，不在源码中增加 inline test module。

## 验证策略

按从小到大的顺序验证：

1. `rs-sanitize` 相关单测；
2. `--no-default-features`、`web`、`http`、`--all-features` matrix；
3. `rs-sanitize` 完整测试、Clippy、Rustdoc、格式和 CI/coverage；
4. `rs-command` 相关测试与完整 CI；
5. `rs-http` sanitizer、error、options、client 相关测试与完整 CI；
6. `rs-mime` 和 `rs-magika` 测试及锁文件依赖图检查。

验证必须确认：

- 所有测试和文档调用点已迁移到结构化 body 返回值；
- `rs-http` 不再搜索或解析标准截断 marker；
- `MaskPolicies`、`FieldSanitizePolicy` 和 `LogSanitizePolicy` 无外部 struct literal；
- `rs-command` Debug 不包含捕获的 secret bytes；
- `rs-mime`、`rs-magika` 锁文件不再包含 `qubit-sanitize 0.2.2`；
- 所有修改仓库均无新 warning。

## 非目标

- 不修改或迁移 `rs-platform`、`rs-llmsdk-core`；
- 不引入任意文本 secret scanner、熵检测、正则词典或厂商 URL path 规则；
- 不把 redaction 值写回业务对象或真实 HTTP 请求；
- 不为 body parser 增加 streaming、decompression 或 capture limit；
- 不改变 `TextBodyPolicy::PassThrough` 的显式风险边界；
- 不批量更改 Rustdoc 的 `# Parameters` 标题；
- 不处理与 sanitizer 无关的下游重构或依赖升级。
