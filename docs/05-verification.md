# 本次验证记录

整理日期：2026-10-26。对象为本目录中的公开示例版文件；没有重跑目标虚拟机。

## 检查结果

| 检查 | 结果 | 能证明什么 |
| --- | --- | --- |
| Windows离线测试 | 335/335通过，0失败 | PowerShell 5.1解析、C#编译、273项构造数据判断及错误/缺失/身份边界测试 |
| Windows测试引擎 | 5.1.26100.8875 / Desktop | 本地测试引擎；不是目标Server 2019的5.1.17763.1 |
| Bash语法 | 15个脚本通过bash -n | Shell语法可解析，未执行采集 |
| 内嵌Python编译 | 14个内嵌块通过compile | Python语法可编译，未执行Python代码或导入脚本 |
| Ubuntu方法表 | 232项编号完整、无重复 | 九领域编号与原项目范围对齐，不代表232项自动检查或合规 |
| Windows映射 | 273项与manifest编号一致；范围台账4685行 | 整理后映射没有漏项 |
| 文件与相对链接 | 已核对本地链接及源码SHA256 | 链接目标在本目录中，整理文件与记录一致 |
| 发布目录敏感项扫描 | 指定模式未命中 | 未发现原资产名、私有IPv4、用户绝对路径、资产特定SID、指定令牌/私钥/URL凭据模式 |
| Git提交前检查 | 在临时目录暂存副本并执行git diff --cached --check | 检查暂存内容的空白问题；没有替用户创建远程仓库 |

Windows实际测试摘要见[windows-offline-summary.json](../tests/windows-offline-summary.json)。目录核对摘要见[portfolio-verification-summary.json](../tests/portfolio-verification-summary.json)。

## 证据边界

- TargetVmExecuted、HostBaselineCollected、NativeQueryMethodsCalled均为false。
- Windows只编译原生包装器，没有调用其系统查询方法。
- 没有在Ubuntu目标环境检查命令存在性、权限、运行结果、完整配置语义或业务兼容性。
- 没有验证任何整改命令，案例仍按原笔记历史证据表述。
- 文本模式扫描不能证明不存在所有秘密；未对原包截图、.7z或历史提交作全面审计。本次发布目录不含这些原始附件。
- 文档中的官方链接用于来源追溯，本次没有把全部网页重新下载核验。

本页的Git提交前检查使用本地临时副本。后续公开仓库发布按[Git操作](06-git-workflow.md)执行，文件与提交一致性需另行核对；发布不会改变上述目标机验证边界。公开前另做了[隐私复查](08-privacy-review.md)。
