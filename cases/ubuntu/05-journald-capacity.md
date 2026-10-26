# U05 journald容量配置

## 来源与范围

原包《Ubuntu_安全加固_手工命令学习记录》§32，2026-10-17复测；对应G05-009。以下“结果”为原笔记记载，本次没有重跑目标机。

## 问题与判断

原查询journal合计约1.2G，合并配置未见相关容量参数显式声明；不能据此推断日志无限增长。本条容量与轮转应满足本地策略，1G/3G是本实验教学值。

## 整改方法

本地备份journald.conf并cmp核对，另保留旧journal目录副本；原记录副本约1.3G，未做逐文件完整性或活动文件一致性验证。编辑[Journal]下：

```ini
SystemMaxUse=1G
SystemKeepFree=3G
```

复查保存内容后，按原方案使用`systemctl restart systemd-journald.service`应用；不要拆成stop再start。

## 复测方法

```bash
systemd-analyze cat-config systemd/journald.conf
systemctl is-active systemd-journald.service
journalctl -u systemd-journald.service -n 10 --no-pager
journalctl --disk-usage
df -h /var/log
```

核对最新启动时间、进程、容量记录及解析错误；journal占用、文件系统剩余空间分别读取。

## 已记录结果

原笔记记录新进程2026-10-17 08:46:41 UTC启动，最新System Journal显示max 1.0G，总占用约1.0G，支持1G容量目标已生效。3G只有未注释配置保存证据。该轮未回传restart退出码或is-active输出，不补记active。

## 回退

预案：恢复本次核对的journald.conf备份，重新启动并复查；保留旧日志副本。恢复配置不能自动找回已清理的归档日志。此项恢复未实际验证。

## 验证边界

只完成两项所选练习，不判整条轮转要求、整个日志组或留存期限通过。SystemMaxUse是容量目标，活动日志及其他使用会影响实际占用；SystemKeepFree不能保证其他进程不耗尽空间。日志中0B free指journal当前限额额度，不是df意义的磁盘已满。
