# Pure parsing and comparison only. Importing this module does not collect host data.
Set-StrictMode -Version 2.0

function Get-RegistryId {
    param($Target)
    return ('{0}|{1}|{2}' -f $Target.Hive,$Target.Key,$Target.Name).ToLowerInvariant()
}

function Test-ExpectedIdentity {
    param($Expected,$Actual)
    $reasons = New-Object 'System.Collections.Generic.List[string]'
    foreach ($field in @('ComputerName','Caption','Version','BuildNumber','ProductType','DomainRole','PartOfDomain','Domain','InstallationType','UBR')) {
        $ep = $Expected.PSObject.Properties[$field]
        $ap = $Actual.PSObject.Properties[$field]
        if ($null -eq $ep -or $null -eq $ap -or $null -eq $ap.Value) {
            $reasons.Add("身份字段缺失：$field")
            continue
        }
        if ($field -eq 'PartOfDomain') {
            if ($ap.Value -isnot [bool] -or $ep.Value -isnot [bool] -or $ap.Value -ne $ep.Value) {
                $reasons.Add("$field 不符：预期=$($ep.Value)，实际=$($ap.Value)")
            }
        } elseif ([string]$ap.Value -ine [string]$ep.Value) {
            $reasons.Add("$field 不符：预期=$($ep.Value)，实际=$($ap.Value)")
        }
    }
    [pscustomobject]@{ Matches=($reasons.Count -eq 0); Reasons=@($reasons.ToArray()) }
}

function Test-RunContext {
    param($Context,$Manifest,[DateTimeOffset]$Now)
    $errors = New-Object 'System.Collections.Generic.List[string]'
    foreach ($name in @('AuthorizationConfirmed','AccountUseConfirmed','LocalAssetScopeConfirmed','RunWindowConfirmed','BaselineConfirmed','ToolUseConfirmed')) {
        $p = $Context.PSObject.Properties[$name]
        if ($null -eq $p -or $p.Value -isnot [bool] -or $p.Value -ne $true) { $errors.Add("$name 尚未确认") }
    }
    foreach ($name in @('ProjectName','Reviewer','AuthorizationBasis','AssetScope','ApprovedRunAccount','ApprovedStart','ApprovedEnd')) {
        $p = $Context.PSObject.Properties[$name]
        if ($null -eq $p -or [string]::IsNullOrWhiteSpace([string]$p.Value)) { $errors.Add("$name 未填写") }
    }
    $hash = $Context.PSObject.Properties['BaselineFileSha256']
    if ($null -eq $hash -or [string]$hash.Value -ine [string]$Manifest.Baseline.SuppliedSha256) { $errors.Add('运行记录中的基线 SHA256 与已映射附件不符') }
    $hostField = $Context.PSObject.Properties['ApprovedComputerName']
    if ($null -eq $hostField -or [string]$hostField.Value -ine [string]$Manifest.ExpectedHost.ComputerName) { $errors.Add('确认的本机资产名与预期主机不符') }
    $start=[DateTimeOffset]::MinValue; $end=[DateTimeOffset]::MinValue
    $sp=$Context.PSObject.Properties['ApprovedStart']; $ep=$Context.PSObject.Properties['ApprovedEnd']
    if ($null -ne $sp -and $null -ne $ep) {
        if ([string]$sp.Value -notmatch '(Z|[+-]\d{2}:\d{2})$' -or [string]$ep.Value -notmatch '(Z|[+-]\d{2}:\d{2})$' -or
            -not [DateTimeOffset]::TryParse([string]$sp.Value,[ref]$start) -or -not [DateTimeOffset]::TryParse([string]$ep.Value,[ref]$end)) {
            $errors.Add('允许运行窗口须填写含时区的 ISO 8601 时间')
        } elseif ($end -lt $start -or $Now -lt $start -or $Now -gt $end) { $errors.Add('当前时间不在确认的允许运行窗口内') }
    }
    [pscustomobject]@{ Allowed=($errors.Count -eq 0); Reasons=@($errors.ToArray()) }
}

function ConvertFrom-SecurityInf {
    param([string]$Text)
    $values=@{}; $section=''; $errors=New-Object 'System.Collections.Generic.List[string]'; $lineNo=0
    foreach ($line in ($Text -split '\r?\n')) {
        $lineNo++; $s=$line.Trim()
        if ($s.Length -eq 0 -or $s.StartsWith(';')) { continue }
        if ($s -match '^\[([^\]]+)\]$') { $section=$Matches[1]; continue }
        if ($s -match '^([^=]+)=(.*)$') {
            $key=$Matches[1].Trim(); $value=$Matches[2].Trim(); $id=($section+'|'+$key).ToLowerInvariant()
            if ($values.ContainsKey($id) -and $values[$id].Value -cne $value) { $errors.Add("冲突的重复条目：$id") }
            $values[$id]=[pscustomobject]@{ Status=$(if($section -eq 'System Access' -and $value.Length -eq 0){'Missing'}else{'Ok'}); Value=$value; Line=$lineNo; Section=$section; Name=$key }
        }
    }
    [pscustomobject]@{ Values=$values; Errors=@($errors.ToArray()) }
}

function Test-ScalarEqual {
    param($Current,$Expected,[string]$Type)
    if ($null -eq $Current) { return $false }
    switch ($Type) {
        'REG_DWORD' {
            $number=0L
            if (-not [Int64]::TryParse([string]$Current,[ref]$number)) { return $false }
            return ($number -eq [Int64]$Expected)
        }
        'Boolean' { return ($Current -is [bool] -and $Current -eq [bool]$Expected) }
        default { return ([string]$Current -ceq [string]$Expected) }
    }
}

function Test-RegistryDataEqual {
    param($Target,$Current)
    if($Target.Type -eq 'REG_SZ' -and $Target.Key -like '*\NetworkProvider\HardenedPaths') {
        $actual=@{};$required=@{}
        foreach($pair in @(@{Text=[string]$Current;Values=$actual},@{Text=[string]$Target.Expected;Values=$required})){
            foreach($part in ($pair.Text -split ',')){
                if($part.Trim() -notmatch '^([A-Za-z]+)\s*=\s*([01])$'){return $false}
                $key=$Matches[1];$value=$Matches[2]
                if($key -notin @('RequireMutualAuthentication','RequireIntegrity','RequirePrivacy')){return $false}
                if($pair.Values.ContainsKey($key)){return $false}
                $pair.Values[$key]=$value
            }
        }
        foreach($key in $required.Keys){if(-not $actual.ContainsKey($key) -or $actual[$key] -ne $required[$key]){return $false}}
        return $true
    }
    if($Target.Type -eq 'REG_SZ' -and [string]$Target.Expected -match '^O:.*D:'){
        try{
            $a=New-Object Security.AccessControl.RawSecurityDescriptor ([string]$Current)
            $b=New-Object Security.AccessControl.RawSecurityDescriptor ([string]$Target.Expected)
            $ab=New-Object byte[] $a.BinaryLength;$bb=New-Object byte[] $b.BinaryLength
            $a.GetBinaryForm($ab,0);$b.GetBinaryForm($bb,0)
            return ([Convert]::ToBase64String($ab) -ceq [Convert]::ToBase64String($bb))
        }catch{return $false}
    }
    return (Test-ScalarEqual $Current $Target.Expected $Target.Type)
}

function Compare-RegistryObservation {
    param($Target,$Observation)
    if ($null -eq $Observation) { return [pscustomobject]@{ State='Error'; Current='本次无采集记录'; Detail='查询记录缺失' } }
    if ($Observation.Status -eq 'Error') { return [pscustomobject]@{ State='Error'; Current='查询失败'; Detail=[string]$Observation.Error } }
    if ($Observation.Status -eq 'Missing') {
        if ($Target.Delete) { return [pscustomobject]@{ State='Match'; Current='未配置（值不存在）'; Detail='成功查询，符合 Excel 中的 delete 要求' } }
        return [pscustomobject]@{ State='Unknown'; Current='未配置（值不存在）'; Detail='不推断系统默认或实际生效值' }
    }
    if ($Observation.Status -ne 'Ok') { return [pscustomobject]@{ State='Error'; Current='未取得'; Detail='无法识别采集状态' } }
    if ($Target.Delete) { return [pscustomobject]@{ State='Mismatch'; Current=[string]$Observation.Value; Detail='基线明确要求此值不存在' } }
    $matched=($Observation.Type -eq $Target.Type -and (Test-RegistryDataEqual $Target $Observation.Value))
    [pscustomobject]@{ State=$(if($matched){'Match'}else{'Mismatch'}); Current=([string]$Observation.Value+' ['+$Observation.Type+']'); Detail='本次实际读取的注册表配置；未据默认值补全' }
}

function New-Evaluation {
    param([string]$Conclusion,[string]$Current,[string]$Status,[string]$Evidence,[string]$Note)
    [pscustomobject]@{ Conclusion=$Conclusion; Current=$Current; CollectionStatus=$Status; Evidence=$Evidence; Note=$Note }
}

function Test-BaselineItem {
    param($Item,[hashtable]$Snapshot)
    if ($Item.Applicable -eq 'No') { return New-Evaluation '不适用' '未采集此不适用条目' '不适用' 'identity.json；检查项映射.csv' $Item.Reason }
    if ($Snapshot.ContainsKey('ComponentNA') -and $Snapshot.ComponentNA.ContainsKey($Item.Id)) {
        return New-Evaluation '不适用' '当前组件不适用' '不适用' 'raw/features.json；raw/optional-features.json' $Snapshot.ComponentNA[$Item.Id]
    }
    $collector=$Item.Collector
    if ($collector -eq 'Registry' -or $collector -eq 'DeviceGuard') {
        $states=New-Object 'System.Collections.Generic.List[string]'; $texts=New-Object 'System.Collections.Generic.List[string]'; $notes=New-Object 'System.Collections.Generic.List[string]'
        foreach ($t in @($Item.Targets)) {
            $id=Get-RegistryId $t; $o=$null
            if ($Snapshot.Registry.ContainsKey($id)) { $o=$Snapshot.Registry[$id] }
            $c=Compare-RegistryObservation $t $o
            $effective=$null
            if ($Snapshot.ContainsKey('Runtime') -and $Snapshot.Runtime.ContainsKey($id)) { $effective=$Snapshot.Runtime[$id] }
            if ($null -ne $effective) {
                $texts.Add("$($t.Name)：配置=$($c.Current)；有效查询=$($effective.Value) [$($effective.Status)，$($effective.Source)]")
                if ($effective.Status -eq 'Ok') {
                    if (-not (Test-ScalarEqual $effective.Value $t.Expected $t.Type)) { $c.State='Mismatch'; $notes.Add('有效值与要求不相同') }
                    elseif ($c.State -eq 'Unknown') { $c.State='Match'; $notes.Add('注册表未配置；以本次有效值查询判定，未推断默认') }
                } elseif ($c.State -eq 'Match') { $c.State='Error'; $notes.Add('策略匹配，但所需的有效值查询失败') }
            } else { $texts.Add("$($t.Name)：$($c.Current)") }
            $states.Add($c.State); $notes.Add($c.Detail)
        }
        if ($states.Count -eq 0) { return New-Evaluation '未检查' '无完整机器值映射' '未覆盖' '检查项映射.csv' $Item.Manual }
        $conclusion='符合'; $status='已采集'
        if ($states.Contains('Mismatch')) {
            $conclusion='不符合'
            if($states.Contains('Error')){$status='已取得差异/部分查询失败'}elseif($states.Contains('Unknown')){$status='已取得差异/部分未配置'}
        }
        elseif ($states.Contains('Error')) { $conclusion='未检查'; $status='查询失败或部分失败' }
        elseif ($states.Contains('Unknown')) { $conclusion='待确认'; $status='未配置/有效值未确认' }
        if ($collector -eq 'DeviceGuard') {
            $notes.Add('UEFI lock、MAT、固件和启动链要求仍需人工核对；当前策略不等于已启用全部保护')
            if($Snapshot.ContainsKey('DeviceGuard')) { $texts.Add('VBS 运行信息='+($Snapshot.DeviceGuard | ConvertTo-Json -Compress -Depth 6)) }
            if ($conclusion -eq '符合') { $conclusion='待确认'; $status='部分自动检查' }
        }
        if ($Item.PolicyPath -like '*Windows Defender*' -and $Snapshot.ContainsKey('MpStatus') -and $conclusion -eq '符合') {
            $m=$Snapshot.MpStatus
            if($m.Status -ne 'Ok' -or @($m.Data).Count -eq 0){$conclusion='待确认';$notes.Add('Defender 引擎状态未取得；有效策略值不能证明引擎正在实施保护')}
            else {
                $p=$m.Data[0].PSObject.Properties['AntivirusEnabled']
                if($null -eq $p -or $p.Value -ne $true){$conclusion='待确认';$notes.Add('Defender Antivirus 未明确处于启用状态；须核对实际保护状态及业务环境')}
            }
        }
        if($Item.Sheet -eq 'User') {
            $notes.Add('本次只读取运行账号 HKCU；其他适用用户及未加载用户配置单元尚未核对')
            if($conclusion -eq '符合'){$conclusion='待确认';$status='当前账号匹配/其他用户未覆盖'}
        }
        return New-Evaluation $conclusion ($texts -join '；') $status 'raw/registry.json；raw/runtime.json；raw/deviceguard.json；raw/gpresult-computer.txt' (($notes | Select-Object -Unique) -join '；')
    }
    $t=$Item.Targets[0]; $o=$null; $type='REG_DWORD'; $expected=$t.Expected; $evidence=''
    switch ($collector) {
        'SecurityDatabase' {
            $evidence='raw/security-merged.inf；raw/security-local.inf；raw/account-policy-native.json；raw/secedit-merged.json；raw/native-query-status.json'
            $id=($t.Section+'|'+$t.Name).ToLowerInvariant()
            if ($Snapshot.Security.Status -eq 'Ok') {
                if ($Snapshot.Security.Values.ContainsKey($id)) { $o=$Snapshot.Security.Values[$id] }
                else { $o=[pscustomobject]@{Status='Missing';Value=$null;Error='导出成功，但条目不存在，不能认定为 0'} }
            } else { $o=$Snapshot.Security }
            if($Snapshot.ContainsKey('AccountPolicy') -and $Snapshot.AccountPolicy.ContainsKey($t.Name)) {
                $effective=$Snapshot.AccountPolicy[$t.Name]
                if($effective.Status -eq 'Ok') {
                    $match=Test-ScalarEqual $effective.Value $expected 'REG_DWORD'
                    $currentText='安全策略数据库='+$(if($o.Status -eq 'Ok'){[string]$o.Value}else{$o.Status})+'；NetUserModalsGet 有效值='+[string]$effective.Value
                    if(-not $match){return New-Evaluation '不符合' $currentText '实际本地账号策略已采集' $evidence '有效策略偏离；不使用数据库缺失或历史值覆盖本次有效值'}
                    if($o.Status -eq 'Ok' -and -not (Test-ScalarEqual $o.Value $expected 'REG_DWORD')){return New-Evaluation '不符合' $currentText '数据库与有效值均采集' $evidence '策略数据库值偏离，虽有效值相同也记录差异；需人工查明来源'}
                    if($o.Status -eq 'Error'){return New-Evaluation '未检查' $currentText '安全数据库查询失败/有效值已采集' $evidence $o.Error}
                    return New-Evaluation '符合' $currentText '实际本地账号策略已采集' $evidence 'NetUserModalsGet(NULL) 只查本机；长度/次数直接比较，密码天数和锁定分钟由 API 秒数换算'
                } elseif($o.Status -eq 'Ok' -and (Test-ScalarEqual $o.Value $expected 'REG_DWORD')) {
                    return New-Evaluation '未检查' ('安全策略数据库='+$o.Value+'；有效值查询失败') '有效查询失败' $evidence $effective.Error
                }
            }
        }
        'Guest' { $o=$Snapshot.Guest; $type='Boolean'; $evidence='raw/local-users.json；按本地 SID RID 501 判定' }
        'UserRights' {
            $evidence='raw/lsa-rights.json；raw/security-merged.inf；raw/native-query-status.json'
            if ($Snapshot.Rights.ContainsKey($t.Name)) { $o=$Snapshot.Rights[$t.Name] }
            if ($null -eq $o -or $o.Status -ne 'Ok') { return New-Evaluation '未检查' 'LSA 用户权限查询失败' '查询失败' $evidence $(if($null -ne $o){$o.Error}else{'查询记录缺失'}) }
            $a=@($o.Sids | Sort-Object -Unique); $b=@($expected | Sort-Object -Unique)
            $same=($a.Count -eq $b.Count -and (($a -join ',') -ceq ($b -join ',')))
            return New-Evaluation $(if($same){'符合'}else{'不符合'}) $(if($a.Count -eq 0){'无人（LSA 成功返回空集合）'}else{$a -join ','}) '实际 LSA 分配' $evidence '比较直接授予的 SID 集合；不展开组成员，不验证已有登录会话令牌'
        }
        'Audit' {
            $evidence='raw/audit-native.json；raw/auditpol.json；raw/native-query-status.json'
            if ($Snapshot.Audit.ContainsKey($t.Guid)) { $o=$Snapshot.Audit[$t.Guid] }
        }
        'Firewall' {
            $evidence='raw/firewall-effective.json；raw/firewall-active.json；raw/firewall-persistent.json'
            $id=$t.Profile+'|'+$t.Property
            if ($Snapshot.Firewall.ContainsKey($id)) { $o=$Snapshot.Firewall[$id] }
            $type=if($t.Property -eq 'Enabled'){'Boolean'}else{'String'}
        }
        default { return New-Evaluation '未检查' '需要人工检查' '未覆盖' '检查项映射.csv' $Item.Manual }
    }
    if ($null -eq $o -or $o.Status -eq 'Error' -or $o.Status -eq 'Unavailable') { return New-Evaluation '未检查' '查询失败/未取得' '查询失败' $evidence $(if($null -ne $o){$o.Error}else{'查询记录缺失'}) }
    if ($o.Status -eq 'Missing') { return New-Evaluation '待确认' '未配置/导出未包含' '未配置/待确认' $evidence '不得把缺失条目当作默认 0 或符合' }
    $current=$o.Value
    if($collector -eq 'Firewall' -and [string]$current -eq 'NotConfigured'){return New-Evaluation '待确认' '未配置（实际有效值尚未确定）' '未配置/待确认' $evidence '不根据 NotConfigured 推断默认入站/出站行为'}
    if ($collector -eq 'Audit' -and [int]$current -eq 4) { $current=0 }
    $same=Test-ScalarEqual $current $expected $type
    if($collector -eq 'Firewall' -and $same -and $Snapshot.ContainsKey('Services')){
        $serviceRows=@($Snapshot.Services.Data | Where-Object {$_.Name -in @('mpssvc','BFE')})
        if($Snapshot.Services.Status -ne 'Ok' -or $serviceRows.Count -ne 2 -or @($serviceRows | Where-Object {$_.State -ne 'Running'}).Count -gt 0){return New-Evaluation '待确认' ([string]$current+'；防火墙相关服务未明确全部运行') '配置匹配/服务实施状态待确认' ($evidence+'；raw/selected-services.json') '检查防火墙服务和过滤引擎状态；没有启动服务，没有测试规则或端口'}
    }
    New-Evaluation $(if($same){'符合'}else{'不符合'}) ([string]$current) '已采集' $evidence $Item.EffectScope
}

Export-ModuleMember -Function Get-RegistryId,Test-ExpectedIdentity,Test-RunContext,ConvertFrom-SecurityInf,Test-ScalarEqual,Compare-RegistryObservation,Test-BaselineItem
