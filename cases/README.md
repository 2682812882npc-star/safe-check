# 整改、复测与回退案例

以下是同包原始笔记的整理摘要，均为个人实验历史记录。命令用于说明当时的操作及复测方法，本次整理没有执行目标机变更。没有纳入原始截图或采集文件，所以“已记录”不等于本仓库可独立重建完整证据链。

| 案例 | 主要内容 | 原笔记支持的状态 |
| --- | --- | --- |
| [U01 SSH配置权限](ubuntu/01-ssh-permissions.md) | 两个配置文件0644→0600 | 所选对象权限复查通过 |
| [U02 sudo伪终端](ubuntu/02-sudo-use-pty.md) | Defaults use_pty | 配置/语法/适用策略通过，实际执行未完成 |
| [U03 SSH Banner及回退纠正](ubuntu/03-ssh-banner-rollback.md) | 提示文案、Banner、选错备份后的纠正 | 首轮有展示记录；重新应用仅用户确认 |
| [U04 密码最长有效期](ubuntu/04-password-age.md) | 默认及所选已有账号99999→365天 | 两处配置复查通过 |
| [U05 journald容量](ubuntu/05-journald-capacity.md) | 1G日志容量目标、3G预留声明 | 1G有运行证据，3G为配置证据 |
| [W01 日志容量](windows/01-event-log-size.md) | 三类日志容量调整 | 原笔记记载配置复查通过 |
| [W02 账户锁定审核](windows/02-account-lockout-audit.md) | 审核账户锁定改为失败 | 原笔记记载配置通过，实际事件待验证 |
| [W03 SMB强制签名](windows/03-smb-signing.md) | 客户端/服务端RequireSecuritySignature | 原笔记记载配置通过，会话与兼容性待验证 |
| [W04 WinRM来源限制](windows/04-winrm-scope.md) | 防火墙远程来源收敛 | 管理来源TCP连通，认证及其他来源拦截待验证 |
| [W05 ASR LSASS规则](windows/05-asr-lsass.md) | 单条规则审核→阻止 | 查询值1，实际阻断及兼容性待验证 |

复用案例结构见[整改模板](../examples/remediation-template.md)；后续真实复测要新建记录和证据，保留该次时间、资产和范围。
