# W04 WinRM防火墙来源限制

## 来源与范围

原包《安全加固 Windows 2019》“第7组：防火墙、端口与服务”。以下“结果”为原笔记记载，本次没有重跑目标机。

## 问题与判断

原WinRM HTTP-In的5985规则允许任意远程IP。原实验将管理来源收敛到指定主机；公开版不携带原管理IP或服务器IP。

## 整改方法

通过VMware控制台保留管理入口，在wf.msc导出原.wfw策略。确认相关规则端口、配置文件、启用状态，将现有相关规则远程地址改为获准管理来源；核对是否仍存在其他宽泛允许规则。新增窄范围规则不能抵消既有宽泛允许规则。

## 复测方法

目标机上查看ActiveStore规则及地址过滤器：

```powershell
Get-NetFirewallRule -PolicyStore ActiveStore -Name 'WINRM-HTTP-In-TCP*' |
    ForEach-Object {
        [pscustomobject]@{
            Name=$_.Name; Profile=$_.Profile; Enabled=$_.Enabled; Action=$_.Action
            RemoteAddress=(($_ | Get-NetFirewallAddressFilter).RemoteAddress -join ', ')
        }
    }
Get-Service WinRM
```

从获准管理源测试：

```powershell
$serverIP = Read-Host '目标实验服务器IP'
Test-NetConnection -ComputerName $serverIP -Port 5985
Test-WSMan -ComputerName $serverIP
```

另需从获准测试的非允许来源确认拦截，并用实际管理认证验证所需功能。

## 已记录结果

原笔记明确记载管理来源到TCP 5985连通正常。没有据此补写Test-WSMan成功、身份认证成功或非授权源已被拦截。

## 回退

预案：管理异常时从VM控制台按本次备份恢复相关规则原地址及状态；全量导入.wfw会覆盖其他规则，先评估。回退未完成验证。

## 验证边界

TCP连通只证明该路径可建立连接。实际认证、非允许来源拦截和全部相关放行规则覆盖待验证；不自动添加TrustedHosts或修改认证策略。
