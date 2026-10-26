# 整理、脱敏与来源说明

## 本次收入

- 15个Ubuntu批次/补查脚本，去除导出时间戳，保留稳定文件名。
- Windows主脚本、纯比较模块、C#只读API包装、离线测试、273项清单及运行记录模板。
- Windows273项检查映射、4685行范围台账，以及Ubuntu九领域方法列。
- Ubuntu/Windows各5个代表案例、结果格式合成示例及记录模板。

## 处理方式

- Ubuntu原实验机名替换为lab-ubuntu20，Windows替换为LAB-SERVER2019；原代码严格身份/版本检查保留。
- Windows移除未被代码使用的历史环境快照，运行记录改为example模板、确认字段默认false。
- 案例账号名示例化为labadmin；WinRM管理IP和服务器IP以角色描述替代，命令通过本地输入获得目标。
- 方法表只抽取方法/要求列，不收录历史当前值、登录记录和资产结论。
- 文档重新组织为相对链接，不携带原来的本机绝对路径、聊天过程或截图引用。
- PowerShell保留UTF-8 BOM以兼容Windows PowerShell 5.1，Shell统一LF。源码映射及前后SHA256见[source-map.json](../tests/source-map.json)。
- 原始G08表存在缺行和汇总矛盾，只补齐方法列，不传播相互冲突的历史统计。ASR案例按完整命令纠正原文漏写的GUID首字符。

## 未收入公开目录

原始采集TXT、环境信息报告、主机结果.7z、74张未逐张审核的PNG、整套原始聊天/学习记录，以及基线PDF/XLSX全文。它们仍在用户原压缩包中，本次没有修改原件。

本次针对最终发布目录进行文本敏感项和凭据模式扫描，范围及结果见[验证记录](05-verification.md)。它不是对原包截图、归档、历史Git提交的全面审计。

所有者指定公开发布后，增加了邮箱、手机号、身份证格式、地址、账号标识、凭据和Git提交身份复查，见[公开前隐私复查](08-privacy-review.md)。

## 基线及命令来源

- Microsoft：Windows 10 v1809 / Windows Server 2019 FINAL（2018-11-20），使用D / WS2019 Member Server列。原映射附件SHA256保留在baseline-manifest.json，用于追溯原实验。
- [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
- [Server 2019最终版基线说明](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-baseline-final-for-windows-10-v1809-and-windows-server-2019/701082)
- CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 / Level 1 Server；条目摘要沿用用户提供的原实验材料。[CIS Ubuntu基线入口](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [systemd v245 journald.conf来源](https://github.com/systemd/systemd/blob/v245/man/journald.conf.xml)、[journald服务手册来源](https://github.com/systemd/systemd/blob/v245/man/systemd-journald.service.xml)
- [shadow 4.8.1 chage手册来源](https://github.com/shadow-maint/shadow/blob/4.8.1/man/chage.1.xml)

以上用于记录原实验依据和解释命令，不表示本次重新获取并验证了所有在线资料。正式项目按当时批准版本和来源复核。第三方基线权利归相应权利人，完整文档通过官方渠道获取。
