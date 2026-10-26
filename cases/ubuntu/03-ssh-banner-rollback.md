# U03 SSH Banner及回退纠正

## 来源与范围

原包《Ubuntu_安全加固_手工命令学习记录》§12～16、§20～22；对应G01-001/002/007。以下“结果”为原笔记记载，本次没有重跑目标机。

## 问题与判断

原issue.net显示发行版及版本，主配置仅见#Banner none。提示文件存在不代表SSH会展示；需要核对Banner配置、适用连接条件和文案。

## 整改方法

保留原SSH会话。备份issue.net及当前主配置；主配置使用`sshd_config.banner.bak`，保留权限整改后的0600。cmp正确配对后，实验提示改为`Authorized users only.`，主配置改为：

```text
Banner /etc/issue.net
```

文案为实验值，真实业务采用批准的提示文本。

## 复测方法

```bash
cat /etc/issue.net
grep -nF 'Banner' /etc/ssh/sshd_config
sshd -t
echo $?
```

检查无错误且退出码0后，核对解析及权限，必要时使用`sshd -T -C ...`指定实际Match条件；再重载`systemctl reload ssh`，建立新连接，核对认证前提示及正常登录。

## 已记录结果

首轮记录cat/grep正确、sshd -t退出码0；用户确认看到提示并正常登录，笔记还记录后续补存认证前提示截图。本公开目录没有携带该截图。

回退时曾误选较早的`sshd_config.bak`。随后改用`sshd_config.banner.bak`纠正；最终文件查询为主配置0600、root:root，issue.net恢复旧文案，主配置为#Banner none。之后重新应用，用户确认“修好了”；该轮没有单独回传完整输出。

## 回退

正确恢复来源是本次变更前的issue.net.bak及sshd_config.banner.bak；恢复后先sshd -t，检查通过再重载并用新连接验证。`cp -p`同时恢复内容及权限属性。

原记录首轮回退sshd -t为0、重载无报错；纠正备份后的sshd -t未报错，但未提供该次退出码、新reload或回退后新连接。

## 验证边界

旧截图对应首轮变更，不能作为回退后重新应用的新证据。恢复备份、语法通过和Banner功能恢复分别记录。Banner仅显示提示，不替代访问控制。
