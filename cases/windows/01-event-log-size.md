# W01 Windows事件日志容量

## 来源与范围

原包《安全加固 Windows 2019》“日志容量加固＋复测”。以下“结果”为原笔记记载，本次没有重跑目标机。

## 问题与判断

原记录Application、Security、System最大容量均20480KB。所选实验目标分别为32768KB、196608KB、32768KB。

## 整改方法

在eventvwr.msc → Windows日志 → 对应日志属性中，先记录原容量、日志模式并按需保存原日志，再修改最大日志大小。其他行为按变更范围核对。

## 复测方法

```powershell
Get-WinEvent -ListLog Application,Security,System |
    Select-Object LogName,
        @{Name='MaximumSizeKB';Expression={$_.MaximumSizeInBytes / 1KB}},
        IsEnabled,LogMode
```

按日志名称逐项对应目标，单位为KB；同时核对启用及保留/覆盖方式。

## 已记录结果

原笔记配有截图并明确记载“三项日志容量整改完成，配置复测通过”。本次只采用这条历史文字结论，没有把未附入仓库的截图描述为本次直接复测。

## 回退

预案：将三个最大容量恢复各自原值，复查容量及日志模式；需要先判断缩容对留存的影响。恢复容量不恢复已覆盖的事件。原记录没有完整回退验证。

## 验证边界

未用填满日志验证覆盖/保留行为，未证明满足实际组织留存天数。
