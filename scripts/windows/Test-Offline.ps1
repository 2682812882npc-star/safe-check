#requires -Version 5.1
<# Offline tests only: no OS/CIM/registry/account/firewall/security queries.
   The runner Invoke-Server2019Baseline.ps1 is parsed, never invoked or dot-sourced.
   The native helper is compiled, but its query methods are never called. #>
[CmdletBinding()]
param([string]$PackagePath='',[string]$OutputDirectory='')
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if([string]::IsNullOrWhiteSpace($PackagePath)){$PackagePath=$PSScriptRoot}
if([string]::IsNullOrWhiteSpace($OutputDirectory)){$OutputDirectory=Join-Path $PSScriptRoot 'offline-tests'}
[void](New-Item -ItemType Directory -Path $OutputDirectory -Force)
$tests=New-Object 'System.Collections.Generic.List[object]'
function Assert-Case {
    param([string]$CaseLabel,[scriptblock]$Body)
    try{& $Body;$tests.Add([pscustomobject]@{Name=$CaseLabel;Passed=$true;Error=''})}
    catch{$tests.Add([pscustomobject]@{Name=$CaseLabel;Passed=$false;Error=$_.Exception.Message})}
}
function Assert-True {param($Value,[string]$Message);if($Value -ne $true){throw $Message}}
function Assert-Equal {param($Actual,$Expected);if([string]$Actual -cne [string]$Expected){throw "预期=$Expected；实际=$Actual"}}
foreach($file in Get-ChildItem -LiteralPath $PackagePath -File | Where-Object {$_.Extension -in @('.ps1','.psm1')}){
    Assert-Case ('PowerShell 5.1 解析：'+$file.Name) {
        $tokens=$null;$parseErrors=$null
        [void][Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$parseErrors)
        Assert-True (@($parseErrors).Count -eq 0) (($parseErrors | ForEach-Object {$_.ToString()}) -join '; ')
    }
}
Assert-Case 'C# 查询包装器编译（不调用系统 API）' {if($null -eq ('BaselineReadOnly.NativeQueries' -as [type])){Add-Type -Path (Join-Path $PackagePath 'ReadOnlyNative.cs') -ErrorAction Stop}}
Import-Module (Join-Path $PackagePath 'Baseline.Core.psm1') -Force -DisableNameChecking
$m=Get-Content -LiteralPath (Join-Path $PackagePath 'baseline-manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-Case '清单完整：273 条明确 D 列要求，262 适用，11 不适用' {Assert-Equal $m.Items.Count 273;Assert-Equal @($m.Items | Where-Object {$_.Applicable -eq 'Yes'}).Count 262;Assert-Equal @($m.Items | Where-Object {$_.Applicable -eq 'No'}).Count 11}
Assert-Case '所有清单项有工作表/行号/原要求/采集方法/人工方法' {foreach($i in $m.Items){Assert-True ($i.Row -gt 1 -and $i.Column -eq 'D' -and -not [string]::IsNullOrWhiteSpace([string]$i.Baseline) -and $i.Targets.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($i.Manual)) $i.Id}}
Assert-Case '固定 Server 2019 独立服务器完整构建号预期' {Assert-Equal $m.ExpectedHost.UBR 1;Assert-Equal $m.ExpectedHost.DomainRole 2;Assert-Equal $m.ExpectedHost.ProductType 3;Assert-Equal $m.ExpectedHost.PartOfDomain False}
$identity=$m.ExpectedHost | ConvertTo-Json | ConvertFrom-Json
Assert-Case '模拟身份一致' {Assert-True (Test-ExpectedIdentity $m.ExpectedHost $identity).Matches '一致身份被拒绝'}
foreach($field in @('ComputerName','Caption','Version','BuildNumber','ProductType','DomainRole','Domain','InstallationType','UBR')){
    Assert-Case ('模拟身份漂移必须停止：'+$field) {
        $a=$identity | ConvertTo-Json | ConvertFrom-Json;$a.$field='DIFFERENT'
        Assert-True (-not (Test-ExpectedIdentity $m.ExpectedHost $a).Matches) '漂移被接受'
    }
}
Assert-Case '模拟入域必须停止' {$a=$identity | ConvertTo-Json | ConvertFrom-Json;$a.PartOfDomain=$true;Assert-True (-not (Test-ExpectedIdentity $m.ExpectedHost $a).Matches) '入域被接受'}
Assert-Case '模拟缺失身份字段不得当作匹配' {$a=[pscustomobject]@{ComputerName='LAB-SERVER2019'};Assert-True (-not (Test-ExpectedIdentity $m.ExpectedHost $a).Matches) '缺失被接受'}
Assert-Case '字符串 False 不能作为未入域布尔值' {$a=$identity | ConvertTo-Json | ConvertFrom-Json;$a.PartOfDomain='False';Assert-True (-not (Test-ExpectedIdentity $m.ExpectedHost $a).Matches) '字符串被错误接受'}
$now=[DateTimeOffset]::Now
$ctx=[pscustomobject]@{AuthorizationConfirmed=$true;AccountUseConfirmed=$true;LocalAssetScopeConfirmed=$true;RunWindowConfirmed=$true;BaselineConfirmed=$true;ToolUseConfirmed=$true;ProjectName='SIMULATION';Reviewer='SIMULATION';AuthorizationBasis='模拟记录，不是实际授权';AssetScope='模拟本机';ApprovedComputerName='LAB-SERVER2019';ApprovedRunAccount='LAB-SERVER2019\Administrator';ApprovedStart=$now.AddMinutes(-1).ToString('o');ApprovedEnd=$now.AddMinutes(1).ToString('o');BaselineFileSha256=$m.Baseline.SuppliedSha256;Exceptions=@()}
Assert-Case '模拟完整运行记录在窗口内' {Assert-True (Test-RunContext $ctx $m $now).Allowed '完整记录被拒绝'}
foreach($name in @('AuthorizationConfirmed','AccountUseConfirmed','LocalAssetScopeConfirmed','RunWindowConfirmed','BaselineConfirmed','ToolUseConfirmed')){
    Assert-Case ('未确认的运行条件拒绝：'+$name) {$c=$ctx | ConvertTo-Json | ConvertFrom-Json;$c.$name=$false;Assert-True (-not (Test-RunContext $c $m $now).Allowed) '未确认状态被接受'}
}
Assert-Case '字符串 true 不能冒充确认布尔值' {$c=$ctx | ConvertTo-Json | ConvertFrom-Json;$c.AuthorizationConfirmed='true';Assert-True (-not (Test-RunContext $c $m $now).Allowed) '字符串被接受'}
Assert-Case '运行窗口已过期拒绝' {Assert-True (-not (Test-RunContext $ctx $m $now.AddMinutes(10)).Allowed) '过期窗口被接受'}
Assert-Case '基线 SHA256 变化拒绝' {$c=$ctx | ConvertTo-Json | ConvertFrom-Json;$c.BaselineFileSha256='changed';Assert-True (-not (Test-RunContext $c $m $now).Allowed) '错误基线被接受'}
Assert-Case '时间没有时区拒绝' {$c=$ctx | ConvertTo-Json | ConvertFrom-Json;$c.ApprovedStart='2026-10-06 01:00:00';Assert-True (-not (Test-RunContext $c $m $now).Allowed) '缺失时区被接受'}
$inf="[System Access]`r`nMinimumPasswordLength = 14`r`n[Privilege Rights]`r`nSeCreateTokenPrivilege = `r`n"
Assert-Case 'INF 解析保留明确空项' {$p=ConvertFrom-SecurityInf $inf;Assert-Equal $p.Values['system access|minimumpasswordlength'].Value 14;Assert-True $p.Values.ContainsKey('privilege rights|secreatetokenprivilege') '空项丢失';Assert-Equal $p.Values['privilege rights|secreatetokenprivilege'].Value ''}
Assert-Case 'INF 冲突重复条目不得静默覆盖' {$p=ConvertFrom-SecurityInf ($inf+"[System Access]`nMinimumPasswordLength=0");Assert-True ($p.Errors.Count -eq 1) '冲突未记录'}
$t=[pscustomobject]@{Hive='HKLM';Key='SOFTWARE\Policies\Simulation';Name='Value';Type='REG_DWORD';Expected=1;Delete=$false}
Assert-Case 'DWORD 精确匹配' {Assert-Equal (Compare-RegistryObservation $t ([pscustomobject]@{Status='Ok';Value=1;Type='REG_DWORD'})).State Match}
Assert-Case 'DWORD 偏差不符合' {Assert-Equal (Compare-RegistryObservation $t ([pscustomobject]@{Status='Ok';Value=0;Type='REG_DWORD'})).State Mismatch}
Assert-Case '同数据错误类型不符合' {Assert-Equal (Compare-RegistryObservation $t ([pscustomobject]@{Status='Ok';Value='1';Type='REG_SZ'})).State Mismatch}
Assert-Case '缺失值不能认定符合' {Assert-Equal (Compare-RegistryObservation $t ([pscustomobject]@{Status='Missing'})).State Unknown}
Assert-Case '访问失败与缺失值区分' {Assert-Equal (Compare-RegistryObservation $t ([pscustomobject]@{Status='Error';Error='模拟拒绝访问'})).State Error}
Assert-Case '查询记录缺失不能符合' {Assert-Equal (Compare-RegistryObservation $t $null).State Error}
Assert-Case '明确删除要求只在成功查询值不存在时匹配' {$x=$t | ConvertTo-Json | ConvertFrom-Json;$x.Delete=$true;Assert-Equal (Compare-RegistryObservation $x ([pscustomobject]@{Status='Missing'})).State Match;Assert-Equal (Compare-RegistryObservation $x ([pscustomobject]@{Status='Ok';Value=0;Type='REG_DWORD'})).State Mismatch;Assert-Equal (Compare-RegistryObservation $x ([pscustomobject]@{Status='Error';Error='模拟失败'})).State Error}
Assert-Case 'UNC 要求按参数比较，允许相同参数换序和更严格附加参数' {$x=[pscustomobject]@{Hive='HKLM';Key='Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths';Name='\\*\SYSVOL';Type='REG_SZ';Expected='RequireMutualAuthentication=1,RequireIntegrity=1';Delete=$false};Assert-Equal (Compare-RegistryObservation $x ([pscustomobject]@{Status='Ok';Value='RequireIntegrity=1, RequireMutualAuthentication=1,RequirePrivacy=1';Type='REG_SZ'})).State Match;Assert-Equal (Compare-RegistryObservation $x ([pscustomobject]@{Status='Ok';Value='RequireIntegrity=0,RequireMutualAuthentication=1';Type='REG_SZ'})).State Mismatch}
Assert-Case 'UNC 冲突重复参数不可判符合' {$x=[pscustomobject]@{Hive='HKLM';Key='Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths';Name='\\*\SYSVOL';Type='REG_SZ';Expected='RequireMutualAuthentication=1,RequireIntegrity=1';Delete=$false};Assert-Equal (Compare-RegistryObservation $x ([pscustomobject]@{Status='Ok';Value='RequireIntegrity=1,RequireIntegrity=0,RequireMutualAuthentication=1';Type='REG_SZ'})).State Mismatch}
Assert-Case 'SDDL 别名与等价 SID 编码可匹配' {$x=[pscustomobject]@{Hive='HKLM';Key='System\CurrentControlSet\Control\Lsa';Name='RestrictRemoteSAM';Type='REG_SZ';Expected='O:BAG:BAD:(A;;RC;;;BA)';Delete=$false};Assert-Equal (Compare-RegistryObservation $x ([pscustomobject]@{Status='Ok';Value='O:S-1-5-32-544G:S-1-5-32-544D:(A;;RC;;;S-1-5-32-544)';Type='REG_SZ'})).State Match;Assert-Equal (Compare-RegistryObservation $x ([pscustomobject]@{Status='Ok';Value='invalid sddl';Type='REG_SZ'})).State Mismatch}
# Every input below is created from expected values. This is not current host configuration.
$snap=@{Registry=@{};Registry32=@{};Runtime=@{};Rights=@{};Audit=@{};Firewall=@{};AccountPolicy=@{};ComponentNA=@{};Guest=[pscustomobject]@{Status='Ok';Value=$false;Error=''};Security=[pscustomobject]@{Status='Ok';Values=@{};Error=''}}
foreach($i in $m.Items){
    foreach($target in $i.Targets){
        switch($i.Collector){
            {$_ -in @('Registry','DeviceGuard')} {$id=Get-RegistryId $target;$snap.Registry[$id]=[pscustomobject]@{Status=$(if($target.Delete){'Missing'}else{'Ok'});Value=$target.Expected;Type=$target.Type;Error=''}}
            'SecurityDatabase' {$id=($target.Section+'|'+$target.Name).ToLowerInvariant();$snap.Security.Values[$id]=[pscustomobject]@{Status='Ok';Value=[string]$target.Expected;Error=''}}
            'UserRights' {$snap.Rights[$target.Name]=[pscustomobject]@{Status='Ok';Sids=@($target.Expected);Error=''}}
            'Audit' {$snap.Audit[$target.Guid]=[pscustomobject]@{Status='Ok';Value=$target.Expected;Error=''}}
            'Firewall' {$snap.Firewall[$target.Profile+'|'+$target.Property]=[pscustomobject]@{Status='Ok';Value=$target.Expected;Error=''}}
        }
    }
}
foreach($i in $m.Items){
    Assert-Case ('全范围模拟判定：'+$i.Id) {
        $r=Test-BaselineItem $i $snap
        $expected=if($i.Applicable -eq 'No'){'不适用'}elseif($i.Collector -eq 'DeviceGuard' -or $i.Sheet -eq 'User'){'待确认'}else{'符合'}
        Assert-Equal $r.Conclusion $expected
    }
}
$regItem=@($m.Items | Where-Object {$_.Id -eq 'Computer-10'})[0];$id=Get-RegistryId $regItem.Targets[0]
Assert-Case '复合条目实际采集缺失为待确认' {$saved=$snap.Registry[$id];try{$snap.Registry[$id]=[pscustomobject]@{Status='Missing';Value=$null;Type='';Error=''};Assert-Equal (Test-BaselineItem $regItem $snap).Conclusion 待确认}finally{$snap.Registry[$id]=$saved}}
Assert-Case '本次访问错误为未检查' {$saved=$snap.Registry[$id];try{$snap.Registry[$id]=[pscustomobject]@{Status='Error';Value=$null;Type='';Error='模拟失败'};Assert-Equal (Test-BaselineItem $regItem $snap).Conclusion 未检查}finally{$snap.Registry[$id]=$saved}}
Assert-Case '本次配置偏差为不符合' {$saved=$snap.Registry[$id];try{$snap.Registry[$id]=[pscustomobject]@{Status='Ok';Value=0;Type='REG_DWORD';Error=''};Assert-Equal (Test-BaselineItem $regItem $snap).Conclusion 不符合}finally{$snap.Registry[$id]=$saved}}
Assert-Case '复合条目保留明确差异并注明其他查询失败' {$it=@($m.Items | Where-Object {$_.Id -eq 'Computer-998'})[0];$k1=Get-RegistryId $it.Targets[0];$k2=Get-RegistryId $it.Targets[1];$s1=$snap.Registry[$k1];$s2=$snap.Registry[$k2];try{$snap.Registry[$k1]=[pscustomobject]@{Status='Ok';Value='DIFFERENT';Type=$it.Targets[0].Type;Error=''};$snap.Registry[$k2]=[pscustomobject]@{Status='Error';Value=$null;Type='';Error='模拟拒绝访问'};$r=Test-BaselineItem $it $snap;Assert-Equal $r.Conclusion 不符合;Assert-True ($r.CollectionStatus -like '*部分查询失败*') '部分查询失败被隐藏'}finally{$snap.Registry[$k1]=$s1;$snap.Registry[$k2]=$s2}}
$right=@($m.Items | Where-Object {$_.Id -eq 'Security_Template-134'})[0]
Assert-Case 'LSA 成功返回空集合才判无人' {Assert-Equal (Test-BaselineItem $right $snap).Conclusion 符合}
Assert-Case 'LSA 查询失败不能判无人' {$name=$right.Targets[0].Name;$saved=$snap.Rights[$name];try{$snap.Rights[$name]=[pscustomobject]@{Status='Error';Sids=@();Error='模拟拒绝访问'};Assert-Equal (Test-BaselineItem $right $snap).Conclusion 未检查}finally{$snap.Rights[$name]=$saved}}
Assert-Case 'SID 额外授予不能因包含推荐 SID 而符合' {$name=$right.Targets[0].Name;$saved=$snap.Rights[$name];try{$snap.Rights[$name]=[pscustomobject]@{Status='Ok';Sids=@('S-1-5-32-544');Error=''};Assert-Equal (Test-BaselineItem $right $snap).Conclusion 不符合}finally{$snap.Rights[$name]=$saved}}
$acct=@($m.Items | Where-Object {$_.Id -eq 'Security_Template-34'})[0]
Assert-Case '安全数据库缺项不能当作零或符合' {$key='system access|minimumpasswordlength';$saved=$snap.Security.Values[$key];try{$snap.Security.Values.Remove($key);Assert-Equal (Test-BaselineItem $acct $snap).Conclusion 待确认}finally{$snap.Security.Values[$key]=$saved}}
Assert-Case '本次账号有效策略偏差优先保留' {$name=$acct.Targets[0].Name;try{$snap.AccountPolicy[$name]=[pscustomobject]@{Status='Ok';Value=0;Error=''};Assert-Equal (Test-BaselineItem $acct $snap).Conclusion 不符合}finally{$snap.AccountPolicy.Remove($name)}}
Assert-Case 'API 秒数换算后非整天偏差不得截断成符合' {$it=@($m.Items | Where-Object {$_.Id -eq 'Security_Template-32'})[0];$key=$it.Targets[0].Name;try{$snap.AccountPolicy[$key]=[pscustomobject]@{Status='Ok';Value=(60.0+1.0/86400.0);Error=''};Assert-Equal (Test-BaselineItem $it $snap).Conclusion 不符合}finally{$snap.AccountPolicy.Remove($key)}}
Assert-Case 'API 秒数换算后非整分钟偏差不得截断成符合' {$it=@($m.Items | Where-Object {$_.Id -eq 'Security_Template-2'})[0];$key=$it.Targets[0].Name;try{$snap.AccountPolicy[$key]=[pscustomobject]@{Status='Ok';Value=(15.0+1.0/60.0);Error=''};Assert-Equal (Test-BaselineItem $it $snap).Conclusion 不符合}finally{$snap.AccountPolicy.Remove($key)}}
Assert-Case '有效策略匹配可解释未配置，不能使用历史值' {$saved=$snap.Registry[$id];try{$snap.Registry[$id]=[pscustomobject]@{Status='Missing';Value=$null;Type='';Error=''};$snap.Runtime[$id]=[pscustomobject]@{Status='Ok';Value=1;Source='SIMULATED effective API';Error=''};Assert-Equal (Test-BaselineItem $regItem $snap).Conclusion 符合}finally{$snap.Registry[$id]=$saved;$snap.Runtime.Remove($id)}}
Assert-Case '有效值与匹配的配置不一致时不符合' {try{$snap.Runtime[$id]=[pscustomobject]@{Status='Ok';Value=0;Source='SIMULATED effective API';Error=''};Assert-Equal (Test-BaselineItem $regItem $snap).Conclusion 不符合}finally{$snap.Runtime.Remove($id)}}
Assert-Case '所需有效查询失败不得当作配置已生效' {try{$snap.Runtime[$id]=[pscustomobject]@{Status='Error';Value=$null;Source='SIMULATED API';Error='模拟查询失败'};Assert-Equal (Test-BaselineItem $regItem $snap).Conclusion 未检查}finally{$snap.Runtime.Remove($id)}}
Assert-Case '组件不适用须有本次明确记录' {try{$snap.ComponentNA[$regItem.Id]='SIMULATED 组件明确未安装';Assert-Equal (Test-BaselineItem $regItem $snap).Conclusion 不适用}finally{$snap.ComponentNA.Remove($regItem.Id)}}
Assert-Case '审核无事件标志 4 不能当作成功/失败' {$it=@($m.Items | Where-Object {$_.Collector -eq 'Audit'})[0];$key=$it.Targets[0].Guid;$saved=$snap.Audit[$key];try{$snap.Audit[$key]=[pscustomobject]@{Status='Ok';Value=4;Error=''};Assert-Equal (Test-BaselineItem $it $snap).Conclusion 不符合}finally{$snap.Audit[$key]=$saved}}
Assert-Case '防火墙 NotConfigured 不能被判定为 Allow/Block' {$it=@($m.Items | Where-Object {$_.Id -eq 'WD_Firewall-3'})[0];$key='Domain|DefaultInboundAction';$saved=$snap.Firewall[$key];try{$snap.Firewall[$key]=[pscustomobject]@{Status='Ok';Value='NotConfigured';Error=''};Assert-Equal (Test-BaselineItem $it $snap).Conclusion 待确认}finally{$snap.Firewall[$key]=$saved}}
Assert-Case '主脚本没有修复/远程/安装/上传命令' {
    $tokens=$null;$errs=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PackagePath 'Invoke-Server2019Baseline.ps1'),[ref]$tokens,[ref]$errs)
    $forbidden=@('Set-ItemProperty','New-ItemProperty','Remove-ItemProperty','Set-NetFirewallProfile','Set-MpPreference','Add-MpPreference','Set-SmbServerConfiguration','Set-SmbClientConfiguration','Set-ExecutionPolicy','Install-Module','Install-Package','Install-WindowsFeature','Enable-WindowsOptionalFeature','Invoke-WebRequest','Invoke-RestMethod','Invoke-Command','New-CimSession','New-PSSession','Restart-Computer','Restart-Service','Stop-Service','Start-Service','Remove-Item','Start-Process')
    $commands=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
    foreach($name in $commands){Assert-True ($name -notin $forbidden) ("发现禁止命令 $name")}
    $text=Get-Content -LiteralPath (Join-Path $PackagePath 'Invoke-Server2019Baseline.ps1') -Raw -Encoding UTF8
    Assert-True ($text -notmatch '(?im)^\s*[^#\r\n]*(gpupdate|/configure|/import|/set|/restore)\b') '发现策略写入/刷新调用'
}
Assert-Case 'C# PInvoke 仅本机查询及释放资源' {
    $text=Get-Content -LiteralPath (Join-Path $PackagePath 'ReadOnlyNative.cs') -Raw
    Assert-True ($text -notmatch 'AuditSet|LsaAdd|LsaRemove|LsaSet|NetUserModalsSet|AdjustTokenPrivileges') '发现策略写入或令牌修改 API'
    Assert-True ($text.Contains('NetUserModalsGet(null, level')) '账号查询没有固定本机'
    Assert-True ($text.Contains('LsaOpenPolicy(IntPtr.Zero')) 'LSA 查询没有固定本机'
    Assert-True ($text.Contains('0x00000801')) 'LSA 查询权限不完整'
    Assert-True (-not $text.Contains('s == 0xC000001A')) '错误 NTSTATUS 被当作空集合'
}
$failed=@($tests | Where-Object {-not $_.Passed})
$report=[pscustomobject]@{TestMode='OFFLINE_SIMULATION_ONLY';Engine=[string]$PSVersionTable.PSVersion;PSEdition=$PSVersionTable.PSEdition;Time=[DateTimeOffset]::Now.ToString('o');Total=$tests.Count;Passed=$tests.Count-$failed.Count;Failed=$failed.Count;TargetVmExecuted=$false;HostBaselineCollected=$false;NativeQueryMethodsCalled=$false;Tests=@($tests.ToArray())}
$report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'test-results.json') -Encoding UTF8
$md=@('# 已完成的代码测试','',('测试时间：'+$report.Time),('测试引擎：Windows PowerShell '+$report.Engine+' / '+$report.PSEdition),('通过：'+$report.Passed+' / '+$report.Total+'；失败：'+$report.Failed),'','执行内容：PowerShell 5.1 语法解析、C# 编译、全部 273 项的模拟判定及错误/缺失/角色漂移等边界测试。','测试数据由基线目标值和明确的模拟偏差构造；没有调用目标虚拟机。','未在物理机执行真实基线采集；没有调用本机 CIM/注册表/账号/防火墙/审核/LSA 查询方法。','C# 只做编译检查，其 PInvoke 系统查询尚未在目标虚拟机执行。','本测试不证明目标主机符合、不证明系统 API 在目标版本上均可访问、不证明业务功能测试通过。')
if($failed.Count -gt 0){$md+=@('','## 失败测试');$md+=@($failed | ForEach-Object {'- '+$_.Name+'：'+$_.Error})}
$md | Set-Content -LiteralPath (Join-Path $OutputDirectory '测试说明.md') -Encoding UTF8
$report | Select-Object TestMode,Engine,Total,Passed,Failed,TargetVmExecuted,HostBaselineCollected,NativeQueryMethodsCalled | Format-List
if($failed.Count -gt 0){exit 1}
