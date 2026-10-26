# U01 SSH配置文件权限

## 来源与范围

原包《Ubuntu_安全加固_手工命令学习记录》§1～5、§21；对应G01-003。以下“结果”为原笔记记载，本次没有重跑目标机。

## 问题与判断

`/etc/ssh/sshd_config`和`/etc/ssh/sshd_config.d/01-lab-baseline.conf`原为root:root、0644。所选规则要求不宽于0600；50-cloud-init.conf原已0600。

## 整改方法

备份两个实际修改对象，用`ls -l`核对元数据，`cmp`按同名文件正确配对比较。原记录曾比较错文件，纠正后两次cmp无差异/报错，未回传退出码。

```bash
chmod 600 /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config.d/01-lab-baseline.conf
```

只修改权限，不加-R。

## 复测方法

```bash
ls -l /etc/ssh/sshd_config /etc/ssh/sshd_config.d/01-lab-baseline.conf
```

通过标准：两个文件均为`-rw-------`、root:root。单纯改变权限无需重载SSH。

## 已记录结果

原笔记记录两个文件均达到0600、root:root。未记录chmod退出码，不补写0。后续Banner回退纠正后，主配置再次确认0600。

## 回退

若只撤销本次权限变更，按原值将这两个文件恢复0644并复查；这会恢复原先不满足所选规则的状态。无需为权限回退覆盖内容。原笔记未单独完成权限回退演练。

## 验证边界

只证明所查两个文件；未验证全部Include范围或SSH全部安全项。
