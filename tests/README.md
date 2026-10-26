# 测试与验证

Windows保留原离线测试入口，以公开版示例身份运行：

```powershell
powershell.exe -NoProfile -File .\scripts\windows\Test-Offline.ps1 -PackagePath .\scripts\windows -OutputDirectory .\offline-tests
```

该命令仅解析、编译和用构造数据测试判断，不调用主采集脚本或原生查询方法。测试输出目录已忽略；适合入Git的筛选摘要见windows-offline-summary.json。

Ubuntu本次只做Bash语法检查和内嵌Python编译，不执行Linux采集，也没有新增功能测试。发布内容、文档链接及方法表覆盖核对见[验证记录](../docs/05-verification.md)。

[source-map.json](source-map.json)保存源码整理前后SHA256及变更说明，可用于确认原始来源。
