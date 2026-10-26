# W05 ASR的LSASS凭据保护规则

## 来源与范围

原包《安全加固 Windows 2019》“第10组：ASR”后续记录。以下“结果”为原笔记记载，本次没有重跑目标机。

## 问题与判断

选定规则9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2由审核模式2改为阻止模式1。原文某处GUID缺少开头9，本文按同段命令及完整GUID纠正。

## 整改方法

先保存规则与动作配对结果并查看审核期业务记录，再通过gpedit.msc对应ASR策略将本条改为1。原笔记提到查看审核事件，但没有完整兼容性验收证据。

## 复测方法

```powershell
$asr = Get-MpPreference
for ($i=0; $i -lt $asr.AttackSurfaceReductionRules_Ids.Count; $i++) {
    if ($asr.AttackSurfaceReductionRules_Ids[$i] -eq '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2') {
        [pscustomobject]@{
            RuleID=$asr.AttackSurfaceReductionRules_Ids[$i]
            Action=[int]$asr.AttackSurfaceReductionRules_Actions[$i]
        }
    }
}
```

必须按索引配对ID和Action，确认该完整GUID对应1；未返回条目不能当作已阻止。

## 已记录结果

原笔记明确记载所选规则查询生效值1，配置为阻止模式。

## 回退

预案：在原策略位置将该规则恢复本次前值2并查询复核；不改其他规则。回退未完成验证。

## 验证边界

实际拦截及业务兼容性待验证，其余ASR规则状态待统一复测。查询值1不等于已发生阻断。
