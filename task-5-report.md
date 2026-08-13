# Task 5 fixture 修复报告

- 将 fixture 中误写入 raw string 的反斜杠移除，使标量生成 JSON token `"raw-unkeyed-secret"`，并使请求体生成 `{"items":[...]}`。
- 已确认测试源文件不含 `\\\"raw-unkeyed-secret`。
- 指定测试已运行；fixture 修正后失败，`allocation_count` 为 283，触发每个标量分配完整 marker 的断言。
