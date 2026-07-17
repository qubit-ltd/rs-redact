# rs-sanitize 截断元数据、Fuzz 与文档同步设计

## 目标

在 `qubit-sanitize 0.3` API 冻结前完成三项收口：让 HTTP body 结果准确表达
“已截断但总长度未知”，为处理不可信结构化输入的 adapter 启用 cargo-fuzz，并同步
Rustdoc 与中英文 README。允许对尚未冻结的公开 API 做破坏性调整。

## 方案比较

评估过三种截断元数据表达方式：

1. **公开来源长度枚举**：用 `BodySourceLength::Known(usize)` 表达已知总长度，用
   `BodySourceLength::UnknownTruncated` 表达已知发生截断但无法得到精确总长度。这是采用
   方案，因为它不能构造 `source_len = None` 且 `truncated = false` 等无意义组合。
2. **`Option<usize>` 加布尔参数**：调用简单，但允许多个互相矛盾的状态，不采用。
3. **把完整 `BodyPreview` 类型移入 core crate**：可以封装字节、长度和展示策略，但会
   把 `rs-http` 的日志上下文与限制策略带入通用 crate，边界过宽，不采用。

Fuzz 直接采用 `.rs-ci` 已支持的标准 cargo-fuzz package。继续只使用 proptest 会遗漏
mutation fuzzing 的组合探索；自建 workflow 则会重复共享 CI，均不采用。

## 公开 API

新增公开非穷尽枚举：

```rust
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodySourceLength {
    Known(usize),
    UnknownTruncated,
}
```

`HttpBodySanitizer::sanitize_body_preview` 的 `source_len: usize` 参数替换为
`source_length: BodySourceLength`。语义如下：

- `Known(total)` 将 `total` 规范为至少 `body_prefix.len()`；规范后的总长度大于 prefix
  长度时表示截断，否则表示调用方提供了完整 capture；
- `UnknownTruncated` 明确表示 source 比 prefix 更长，但总长度未知；
- `sanitize_body` 始终产生已知且未截断的来源长度。

`BodySanitization` 独立保存 `source_len: Option<usize>` 和 `truncated: bool`，公开方法调整为：

```rust
pub const fn source_len(&self) -> Option<usize>;
pub const fn truncated_bytes(&self) -> Option<usize>;
pub const fn is_truncated(&self) -> bool;
```

`truncated_bytes` 仅在精确总长度已知时返回 `Some`；未知总长度返回 `None`。标准渲染规则：

- 未截断：不追加后缀；
- 已知总长度截断：`...<truncated N bytes>`；
- 未知总长度截断：`...<truncated>`。

非 UTF-8 binary body 在未知总长度截断时输出
`<binary more than N bytes>...<truncated>`，其中 `N` 是 capture 长度；不伪造精确总长度。

## 完整 Capture 与 Preview 语义

内部继续保留 complete/preview 展示差异：空 complete body 输出空字符串，空 preview
输出 `<empty>`。结构化解析失败原因改为依据是否真实截断：

- 未截断 preview 的非法 JSON、NDJSON 或 form 使用 `InvalidJson`、`InvalidNdjson`、
  `InvalidFormUrlEncoded`；
- 真实截断 preview 使用对应的 `InvalidOrTruncated*`；
- multipart 仍在任何截断状态下整体 redaction。

这样 presentation mode 不再和 capture completeness 混为同一个状态。

## rs-http 迁移

`BodyPreview::new` 持有完整 body，因此即使 limit 切出 prefix，也能传递
`BodySourceLength::Known(full_len)`。

`BodyPreview::from_limited_bytes` 用于流式错误响应。`truncated = true` 时只知道后续仍有
数据，传递 `BodySourceLength::UnknownTruncated`；否则传递已知总长度。错误响应继续使用
自己的非计数后缀，但不再用 `limit + 1` 假装精确总长度。

`BodySourceLength` 只用于 `rs-http` 内部集成，不从 `qubit-http` crate root 重导出。

## Fuzz 设计

新增标准 `fuzz/` package，并声明 `[package.metadata] cargo-fuzz = true`。包含两个 target：

1. `http_body`：从输入字节派生 Content-Type、match mode、known/unknown source length 和
   body bytes，调用完整 body 与 preview API，验证不 panic、`captured_len` 不变量、精确
   长度不小于 capture，以及相同输入结果确定。
2. `web_inputs`：把任意字节送入 form sanitizer；可解析为 UTF-8 时也构造 URL query，
   覆盖 percent encoding、重复字段和 Unicode 边界。验证不 panic 和确定性。

seed corpus 覆盖 malformed percent escapes、重复 boundary/name 参数、转义引号、混合
CRLF/LF、非 UTF-8、截断 JSON/NDJSON/form/multipart。常规 CI 只执行共享脚本定义的限时
smoke fuzz，不增加独立 workflow。

## 文档同步

- `sanitize_body` Rustdoc 明确完整 API 不设置内部大小限制，不可信或大 body 应由调用方
  限制后使用 preview API；
- README 的 preview 示例迁移到 `BodySourceLength`；
- 中英文 README 都补充 `[`、`]` canonicalization 行为；
- 中文 README 补齐新增数据库凭据字段，并把“自定义字段”标题移动到 strongest/remove
  说明之前，与英文结构一致；
- 文档解释已知与未知截断后缀，不宣称未知总长度具有精确截断字节数。

## 测试与验证

实现严格执行 TDD：

1. 先修改/新增 `BodySanitization` 测试，要求未知长度返回 `None` 并渲染非计数后缀；
2. 先增加未截断 preview 使用完整-body解析失败原因的回归测试；
3. 先迁移 `rs-http` 测试，固定流式未知总长度和普通已知总长度行为；
4. 再实现最小 API 与下游迁移；
5. fuzz 配置通过 `cargo fuzz list`、build 和共享 smoke 检查验证；
6. 最后分别运行 `rs-sanitize` 与 `rs-http` 的项目验证命令。

## 非目标

- 不增加通用 secret scanner、正则词典或熵检测；
- 不把 URL path、shell payload、解压或日志上下文策略移入 `rs-sanitize`；
- 不新增独立 form Cargo feature；
- 不修改 `rs-json`、`rs-config` 或 `rs-mixin`；
- 不提交、推送或合并 git 变更。
