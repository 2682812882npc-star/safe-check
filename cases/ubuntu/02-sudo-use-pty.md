# U02 sudo伪终端

## 来源与范围

原包《Ubuntu_安全加固_手工命令学习记录》§6～11；对应G03-006。以下“结果”为原笔记记载，本次没有重跑目标机。

## 问题与判断

所查配置未见use_pty显式声明。该选项用于sudo通过终端运行命令时使用独立伪终端，不会自动收紧sudo授权或启用完整输入输出审计。

## 整改方法

保留现有root会话。原记录有sudoers备份元数据，但修改前cmp结果未回传。通过`EDITOR=nano visudo`编辑主配置，增加：

```text
Defaults use_pty
```

有语法错误先修正，不强制保存。

## 复测方法

```bash
visudo -c
grep -nF 'use_pty' /etc/sudoers /etc/sudoers.d/*
sudo -l -U labadmin
```

`labadmin`为公开示例名，应使用已有获准账号。检查有效声明、是否存在`!use_pty`及作用域覆盖，核对指定账号Matching Defaults。实际执行须在该账号会话、已获准命令范围内验证，例如`sudo id`；不要把root查询规则当作成功认证。

## 已记录结果

原笔记记录：visudo -c对主配置及README为parsed OK；grep检出Defaults use_pty；所查账号Matching Defaults含use_pty，授权为(ALL : ALL) ALL。实际sudo执行认证失败，之后用户说明忘记密码并跳过，执行验证未完成。

## 回退

预案：保留root会话，通过visudo仅删除本次新增行，再visudo -c；不盲目覆盖已有其他修改的旧文件。此项回退未执行。

## 验证边界

配置、语法和所查账号适用规则已核对。未证明成功执行sudo、直接观察到伪终端或所有sudo场景正常；不把认证失败归因于新增选项。
