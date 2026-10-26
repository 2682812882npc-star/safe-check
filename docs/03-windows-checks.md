# Windows Server 2019检查

## 文件

| 文件 | 用途 |
| --- | --- |
| [Invoke-Server2019Baseline.ps1](../scripts/windows/Invoke-Server2019Baseline.ps1) | 身份及运行记录检查、本机批量采集、结果输出 |
| [Baseline.Core.psm1](../scripts/windows/Baseline.Core.psm1) | 纯解析与比较函数，导入不采集主机配置 |
| [ReadOnlyNative.cs](../scripts/windows/ReadOnlyNative.cs) | 只读Windows API包装；运行时Add-Type编译 |
| [baseline-manifest.json](../scripts/windows/baseline-manifest.json) | 273项原要求及机器目标值，ExpectedHost示例 |
| [run-context.example.json](../scripts/windows/run-context.example.json) | 未填写的本机运行记录模板 |
| [Test-Offline.ps1](../scripts/windows/Test-Offline.ps1) | 离线解析、编译与模拟判断测试，不调用真实采集 |

## 覆盖

| 类别 | 明确要求 | 预期适用 | 静态不适用 |
| --- | ---: | ---: | ---: |
| Security Template | 65 | 57 | 8 |
| Adv Audit Config | 23 | 23 | 0 |
| WD Firewall | 9 | 9 | 0 |
| Computer | 175 | 172 | 3 |
| User | 1 | 1 | 0 |
| 合计 | 273 | 262 | 11 |

262个预期适用项目中，260个可做配置层自动判断；VBS平台/锁定与其他用户覆盖2项仍部分自动。组件查询失败不自动形成不适用。

完整[检查项映射](mappings/windows-检查项映射.csv)包含原工作表行号、目标值、人工入口、判定层次；[全表范围台账](mappings/windows-全表范围台账.csv)说明其他命名策略行为何纳入/排除。

## 运行前适配

公开版`LAB-SERVER2019`是示例名，UBR=1是历史实验预期，不能直接当作你的当前配置。

1. 在目标实验VM内核对实际主机、Caption/Version/BuildNumber/UBR、角色、是否入域、工作组和安装类型。按实据审核`baseline-manifest.json`中的`ExpectedHost`。原脚本另外要求VMware、独立服务器及Server 2019；保留这些检查。
2. 在同目录复制模板为`run-context.json`。填写本次审核人、资产范围、账号、含时区的运行窗口等；六个确认字段保持真实状态。模板默认false。运行记录属于本地文件，已被gitignore排除。
3. `BaselineFileSha256`核对的是原映射基线附件的SHA256，不是JSON自身哈希。若更换基线版本或附件，应重做映射及比较，不能只换哈希。
4. 文件在本地磁盘，使用目标VM的64位Windows PowerShell 5.1 Desktop、FullLanguage、管理员终端。脚本不更改执行策略。
5. 更换ExpectedHost后，原离线测试中固定UBR=1的历史断言也需审核适配，不应删掉断言或放松身份限制来获得通过。

在目标VM本地目录中，审核完成后运行：

```powershell
Copy-Item .un-context.example.json .un-context.json
# 用文本编辑器填妥run-context.json，并核对ExpectedHost后执行：
powershell.exe -NoProfile -File .\Invoke-Server2019Baseline.ps1 -RunContextPath .un-context.json -OutputRoot .esults
```

复制模板只需首次执行；已有本次记录时先检查，避免覆盖。

## 证据与判定

- 账户/锁定：本地与合并secedit导出；NetUserModalsGet(NULL)读取本机有效值，保留原单位及换算。
- 用户权限：LSA按SID读取直接授予的完整集合，区分成功空集合和失败。
- 审核：按GUID批量读取系统有效值，另存auditpol输出。
- 防火墙：ActiveStore、PersistentStore与COM有效动作；NotConfigured不直接转成Allow/Block。
- 注册表：类型和值均比较，部分IE策略另查32位视图；HKCU只覆盖当前账号。
- SMB、Defender、ASR、日志、WinRM：用本机有效查询补充配置；WinRM未明确运行时不启动服务。

每次新建结果目录，含identity、raw、结果CSV/JSON、人工复核队列、例外表和SHA256清单。出现停止原因且没有完整结果表时，只能称为启动记录或部分采集。

代码测试看[验证说明](05-verification.md)，手工整改实例看[案例索引](../cases/README.md)。
