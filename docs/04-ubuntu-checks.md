# Ubuntu 20.04检查

## 九领域方法表

[ubuntu-检查方法.csv](mappings/ubuntu-检查方法.csv)只保留编号、检查项、位置/含义、原笔记要求、对应脚本、来源和行号，未收录主机实际输出或历史合规结论。

| 领域 | 内容 | 方法表已整理 / 原笔记列明项数 |
| --- | --- | ---: |
| G01 | SSH登录 | 22 / 22 |
| G02 | 密码策略与失败锁定 | 30 / 30 |
| G03 | 账号与sudo权限 | 29 / 29 |
| G04 | 防火墙与端口暴露 | 11 / 11 |
| G05 | 日志与时间同步 | 25 / 25 |
| G06 | 服务、软件与更新 | 29 / 29 |
| G07 | 文件权限与计划任务 | 26 / 26 |
| G08 | 文件系统隔离与挂载 | 21 / 21 |
| G09 | 内核、网络与系统保护 | 39 / 39 |

这些是项目自定义分组编号，不是CIS原始编号。要求摘要沿用原笔记，未在本次整理中把每项重新对照最新官方基线。工作中应再核对该项目批准版本、原文条目、适用级别和例外。

详细记录中G08-009～014缺行，本次用同包汇总表的“方法列”补齐；没有补造这些条目的当前值或检查结果。

G05-010～016的方法来自同包脚本的静态ITEMS定义。原实验采用rsyslog时，这七项独立journald要求需先核对适用性。

## 15个已有脚本

| 批次 | 文件 | 范围 |
| --- | --- | --- |
| G01-001～007 | [g01_001_007_compact.sh](../scripts/ubuntu/g01_001_007_compact.sh) | 提示内容、文件/密钥权限、访问名单、Banner |
| G01-008～015 | [g01_008_015_compact.sh](../scripts/ubuntu/g01_008_015_compact.sh) | 算法、连接、认证、日志 |
| G01-016～022 | [g01_016_022_compact.sh](../scripts/ubuntu/g01_016_022_compact.sh) | 会话、空口令、root登录、PAM |
| G02-001～007 | [g02_001_007_compact.sh](../scripts/ubuntu/g02_001_007_compact.sh) | PAM包与模块接入 |
| G02-008～017 | [g02_008_017_compact.sh](../scripts/ubuntu/g02_008_017_compact.sh) | 密码质量和失败锁定 |
| G02引用补查 | [g02_pam_routes.sh](../scripts/ubuntu/g02_pam_routes.sh) | PAM引用与控制流线索，不新增基线项目 |
| G02-018～024 | [g02_018_024_compact.sh](../scripts/ubuntu/g02_018_024_compact.sh) | 历史密码及pam_unix |
| G02-025～030 | [g02_025_030_compact.sh](../scripts/ubuntu/g02_025_030_compact.sh) | 默认有效期等；账号实际值仍有人工边界 |
| G03-001～004 | [g03_001_004_compact.sh](../scripts/ubuntu/g03_001_004_compact.sh) | 登录提示与权限 |
| G03-005～010 | [g03_005_010_compact.sh](../scripts/ubuntu/g03_005_010_compact.sh) | sudo与su声明 |
| G03-011～014 | [g03_011_014_compact.sh](../scripts/ubuntu/g03_011_014_compact.sh) | 特权编号和root密码状态边界 |
| G03-015～018 | [g03_015_018_compact.sh](../scripts/ubuntu/g03_015_018_compact.sh) | root环境与系统账号 |
| G03-019～029 | [g03_019_029_compact.sh](../scripts/ubuntu/g03_019_029_compact.sh) | 超时、umask、账号/组与家目录 |
| G04-001～011 | [g04_001_011_compact.sh](../scripts/ubuntu/g04_001_011_compact.sh) | 监听端口与UFW方案 |
| G05-010～016 | [g05_010_016_compact.sh](../scripts/ubuntu/g05_010_016_compact.sh) | 独立journald方案；原实验rsyslog方案下需先确认适用性 |

其余G05批次及G06～G09没有随包脚本，不把文档记录写成源码齐全或可一键检查。G04也不等于所有nftables/iptables方案都有脚本。

## 运行方法

所有脚本保留完整`uname -s -n -r -m`身份比较。公开版示例为`Linux lab-ubuntu20 5.4.0-216-generic x86_64`。运行前对照获准实验机的实际输出，审核修改本次将使用的脚本预期字符串；不要通过改主机名或删检查迎合示例。

在Ubuntu已有root终端运行选定批次，需要Bash及Python3；脚本不负责安装或自动提权。先切到本地证据目录，再用脚本绝对路径运行，输出会写到当前目录：

```bash
# 路径按实际位置替换；目录仅用于保存本次本地证据。
mkdir -p /root/baseline-results/session-01
cd /root/baseline-results/session-01
bash /opt/host-baseline-lab/scripts/ubuntu/g01_001_007_compact.sh
```

不要使用source。每批有结果与详细证据TXT；保留错误、退出码、采集结束说明，先处理缺口，再人工判断。检查脚本不会替你修改策略。

G05如已明确采用rsyslog，可用`--logging rsyslog`记录选择；默认auto只是从本机服务推断线索。不能为了跑出“符合”擅自改选日志方案。

## 人工核查抓手

| 领域 | 核查入口 | 关注点 |
| --- | --- | --- |
| SSH | 配置、Include/Match、权限、`sshd -t`及必要时`sshd -T` | 文本、解析、新连接展示分别记录；不要读取私钥正文 |
| 口令/PAM | dpkg状态、现存APT候选、PAM引用、login.defs、`chage -l <账号>` | 默认策略不等于已有账号；只查所需状态，不导出shadow正文 |
| sudo/账号 | `visudo -c`、`sudo -l -U <账号>`、UID/GID及元数据 | 作用域、授权、认证和执行分别核对 |
| 防火墙 | `ss -lntu`、UFW状态/规则和当前服务 | 协议、来源、地址、IPv4/IPv6、业务用途；不以监听即判漏洞 |
| 日志/时间 | systemd合并配置、服务状态、`journalctl --disk-usage` | 区分rsyslog/独立journald；容量及留存按本地策略 |
| 软件/服务 | 包数据库、本地源配置、systemctl查询 | 缓存并非在线最新；服务存在不代表有必要关闭 |
| 文件/任务 | stat、账号组映射、cron/at入口、软件包来源 | 容器UID映射、服务账号例外、特殊权限文件用途 |
| 挂载 | `findmnt`、fstab、当前挂载与启动单元 | 独立挂载前提与nodev/nosuid/noexec分开判断 |
| 内核/系统 | proc/sys、sysctl.d、模块配置、AppArmor | 当前值与持久配置、模块存在/已加载/被禁止分别核对 |

命令只是入口，预期值依方法表及已确认基线而定；本次没有在目标Ubuntu上执行这些命令。
