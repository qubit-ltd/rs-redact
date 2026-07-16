# rs-sanitize 最终安全收口设计

## 目标

在 `qubit-sanitize 0.3.0` API 稳定前完成最后一轮聚焦加固，并同步修正
`qubit-http` 对 sanitizer 安全边界的使用。范围严格限定为已确认的九项：不透明文本
默认策略、multipart 文件优先级、preset 合并语义、默认凭据名、方括号字段名、
multipart 日志控制字符、URL path 策略、公开常量演进性，以及安全关键函数的可审计性。

本次不增加通用 secret scanner、正则词典、熵检测、厂商 webhook 解析或任意文本内容
分析器。

## 方案选择

评估过三种实现方式：

1. **只修复已确认的两个泄漏点**：差异最小，但继续保留模糊的 `Sanitized` 状态、
   `rs-http` 隐式透传和难以配置的 URL path 边界。
2. **聚焦的策略化收口**：修复具体泄漏，并把 opaque text 与 URL path 变成明确、
   可测试的策略；同时完成低成本 API 演进修正。这是采用方案。
3. **通用内容扫描**：尝试识别任意文本、path 和 JSON scalar 中的秘密。误报、漏报和
   维护成本均过高，且违背 crate 的结构化字段职责，不采用。

## rs-sanitize 行为设计

### BodySanitizationStatus

新增非穷尽枚举成员：

```rust
PassedThrough
```

顶层 `text/*` 在 `TextBodyPolicy::PassThrough` 下返回 `PassedThrough`，不再返回
`Sanitized`。multipart 可能同时包含结构化脱敏内容和原样文本，因此 multipart
sanitizer 返回内部结果，携带 `contains_passed_through_text`；只要任一 part 原样输出，
整个 body 的状态为 `PassedThrough`。`Sanitized` 只表示输出没有采用 opaque-text
明文透传。

该内部结果使用私有类型 `MultipartSanitization` 表达，放在
`src/adapter/http/internal/multipart_sanitization.rs`，避免用 `(String, bool)` 元组
隐藏状态含义。类型只暴露 crate 内所需的 content 与 pass-through 状态。

### multipart 文件与字段名

任何存在 `filename` 或 `filename*` 的 part 都在字段敏感度判断之前返回
`<redacted: file part>`。字段名仍使用原始值进行敏感匹配，但写入 summary 前通过
`escape_debug` 风格转义控制字符；可打印字段名保持现有展示格式。

为降低 `sanitize_multipart_part` 的分支复杂度，新增私有类型
`MultipartPartMetadata`，放在
`src/adapter/http/internal/multipart_part_metadata.rs`。它只负责保存已解析的
`name`、`filename` 和 `content_type`，不扩大公开 API，也不改变 multipart marker。

### preset strongest 语义

`SensitiveFields::extend_preset` 改用 `insert_strongest`。因此
`FieldSanitizer::extend_preset` 与其他名为 add/extend 的 facade 保持一致，不能降低
已有等级。显式降低仍通过现有 `insert` 或 `set_sensitive_field_level` 完成，不新增
重复覆盖 API。

### 默认字段

Credentials preset 增加：

| 字段 | 等级 | 原因 |
| --- | --- | --- |
| `secret_key` | `Secret` | 常见框架或服务的主密钥名称 |
| `secret_access_key` | `Secret` | 云凭据秘密部分 |
| `access_key` | `High` | 泛化名称可能直接承载可用凭据 |
| `access_key_id` | `Medium` | 通常是凭据标识符，保留最小诊断后缀 |

这些是明确字段名，不把 `key` 变成通用 suffix，以避免大面积误报。

### 方括号字段边界

`[` 与 `]` 加入字段分隔符集合，并在 canonicalization 时移除。这样
`user[password]`、`credentials[api_key]` 可通过 `ExactOrSuffix` 命中，同时继续保证
`notpassword` 不命中 `password`。该规则位于 core，因此 URL query、form、HTTP body、
argv 和 env 获得一致语义。

### 公开常量

`DEFAULT_EXTRA_FIELDS` 从固定长度数组改为公开 slice：

```rust
pub const DEFAULT_EXTRA_FIELDS: &[(&str, SensitivityLevel)] = &[...];
```

调用点按 slice 迭代，后续增加默认字段不再改变常量的公开数组长度类型。

### HTTP body 分发复杂度

保持 `HttpBodySanitizer::sanitize_body_inner` 的签名和公开调用路径不变，把分支拆成
私有的 multipart、NDJSON、JSON、form 和 fallback 处理方法。每个方法继续返回
`BodySanitization`，共享现有 source-length 和 marker 语义。这里只拆责任，不改变
content-type 优先级或 sniffing 规则。

## rs-http 集成设计

### opaque text 策略

`LogSanitizePolicy` 新增 `text_body_policy: TextBodyPolicy`，默认值为 `Redact`。提供
getter、setter 和 `with_text_body_policy`；`qubit-http` 从 crate root 重导出
`TextBodyPolicy`，调用方不需要直接依赖兼容版本的 `qubit-sanitize`。

`LogSanitizer::new` 使用 policy 中的值，不再无条件选择 `PassThrough`。TRACE 请求/
响应 body 和非成功响应的 `HttpError.message` 使用同一策略。需要原样诊断文本的调用方
必须显式设置 `TextBodyPolicy::PassThrough`。

### URL path 策略

新增公开非穷尽枚举 `UrlPathPolicy`，放在
`rs-http/src/sanitize/url_path_policy.rs`：

```rust
#[non_exhaustive]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum UrlPathPolicy {
    #[default]
    Preserve,
    Redact,
}
```

该策略属于 HTTP 日志契约，不放进通用 `UrlSanitizer`。`LogSanitizePolicy` 持有它并
提供 getter、setter、with 方法。`Preserve` 保持兼容；`Redact` 在调用 core URL
sanitizer 前把完整 path 替换为固定 marker，同时仍由 core 掩码 userinfo、password、
fragment 和敏感 query。所有 Rustdoc/README 删除绝对的 “log-safe” 承诺，明确 path
默认保留，业务秘密 path 必须显式选择 `Redact`。

## 方法组织与 inline

涉及文件按以下顺序整理 inherent methods：构造器和 builder 风格 `with_*` 优先；
其后按可见性排列 public getter、setter，再是 restricted/private 方法。现有
`FieldSanitizePolicy` 与 `MaskPolicies` 的 `with_*` 位于 getter 前符合构造器优先规则，
不做无意义重排。getter、setter 和纯转发 facade 使用 `#[inline(always)]`，短小非纯
转发函数使用 `#[inline]`，复杂分发方法不添加 inline。不为了本次任务重排无关类型。

## 测试设计

所有测试继续位于与源码镜像的 `tests/` 目录，严格采用 TDD：每项先增加失败回归测试
并确认失败原因，再写最小实现。

`rs-sanitize` 增加：

- Low/Medium 敏感字段名的 multipart 文件仍完整 redaction；
- multipart 字段名控制字符被转义，普通字段名格式不变；
- `extend_preset` 不降低已有 `Secret`；
- `SECRET_KEY`、`AWS_SECRET_ACCESS_KEY`、`AWS_ACCESS_KEY_ID` 的等级与输出；
- `user[password]`、`credentials[api_key]` 命中以及 `notpassword` 不误判；
- 顶层和 multipart opaque text 的 `PassedThrough` 状态；
- `DEFAULT_EXTRA_FIELDS` slice API 可用；
- body dispatch 重构前后的 marker、长度和 content-type 优先级保持不变。

`rs-http` 增加：

- 默认 TRACE text body、multipart text part 和错误响应 text preview 被 redaction；
- 显式 `PassThrough` 恢复原样输出；
- 默认 URL path 保留但文档边界准确；
- 显式 `UrlPathPolicy::Redact` 不输出原始 path，query/userinfo 仍正常脱敏；
- policy getter、setter、with 方法及 debug strongest 合并保持策略值。

## 兼容性与下游

- `BodySanitizationStatus` 已是 `#[non_exhaustive]`，增加 variant 不要求下游穷尽修改；
- `rs-http` 默认 opaque text 从明文变为 redaction，是有意的安全行为变化；
- URL path 默认仍为 Preserve，避免无提示改变现有诊断信息；
- `rs-command` 无 API 迁移，只通过默认字段和 bracket 语义获得加强；
- `rs-mime`、`rs-magika` 不修改，现有未提交 SPI/provider 变更保持原样；
- 不执行 git commit、push 或跨仓库混合提交。

## 验证顺序

每个行为先运行最小相关测试完成 RED/GREEN。全部实现后，在每个被修改 crate 内严格
按仓库顺序执行：

1. `./align-ci.sh`；
2. `./ci-check.sh`；
3. 仅当 CI 报告覆盖率低于阈值时执行 `./coverage.sh json`；
4. 重新检查格式化产生的 diff、公开 API、模块 re-export 和下游本地 path 依赖。
