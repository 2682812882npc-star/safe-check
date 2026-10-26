# W03 SMB强制签名

## 来源与范围

原包《安全加固 Windows 2019》“第11组：SMB签名”；Security Template行76/81。以下“结果”为原笔记记载，本次没有重跑目标机。

## 问题与判断

所选两项要求客户端及服务器端RequireSecuritySignature=True。客户端控制本机访问共享，服务器端控制其他机器访问本机共享，两侧分开判断。

## 整改方法

修改前导出安全策略并保存Get-SmbClientConfiguration/Get-SmbServerConfiguration选定字段。secpol.msc → 本地策略 → 安全选项，将两个“对通信进行数字签名（始终）”设为已启用。

## 复测方法

```powershell
[pscustomobject]@{
    ClientRequireSecuritySignature = (Get-SmbClientConfiguration).RequireSecuritySignature
    ServerRequireSecuritySignature = (Get-SmbServerConfiguration).RequireSecuritySignature
    EnableSMB1Protocol = (Get-SmbServerConfiguration).EnableSMB1Protocol
    EnableSMB2Protocol = (Get-SmbServerConfiguration).EnableSMB2Protocol
}
```

通过标准为两个Require字段True，另核对原协议状态未被意外改变。

## 已记录结果

原笔记记载两项配置复测通过，SMB1保持禁用，SMB2/3保持启用。

## 回退

预案：依修改前导出与实际原值恢复两项，再检查新共享会话及必要业务。原笔记未给出足以公开重建的全部原值，此处不编造回退命令。

## 验证边界

实际共享连接、会话签名、旧客户端兼容性及回退验证待完成。
