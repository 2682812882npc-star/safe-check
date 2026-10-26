#requires -Version 5.1
<#
只读、本机、人工审核后运行。仅写入本次结果目录。
启动时核对 LAB-SERVER2019 / Server 2019 / 独立服务器 / 未入域 / 完整构建号。
此脚本不含修复、策略导入、策略刷新、安装、重启、远程会话或上传操作。
#>
[CmdletBinding()]
param(
    [string]$RunContextPath = '',
    [string]$OutputRoot = ''
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if([string]::IsNullOrWhiteSpace($RunContextPath)){$RunContextPath=Join-Path $PSScriptRoot 'run-context.json'}
if([string]::IsNullOrWhiteSpace($OutputRoot)){$OutputRoot=Join-Path $PSScriptRoot 'results'}
$started=[DateTimeOffset]::Now
$manifest=$null; $identity=$null; $runDir=$null; $rawDir=$null
$approvedEnd=[DateTimeOffset]::MinValue

function Assert-WindowOpen {
    if([DateTimeOffset]::Now -gt $approvedEnd){throw '确认的运行窗口已经结束，停止后续采集。'}
}

function Assert-LocalFilePath {
    param([string]$Path)
    $full=[IO.Path]::GetFullPath($Path)
    if ($full.StartsWith('\\') -or $full -match '^[^:]+::' -or $full -notmatch '^[A-Za-z]:\\') { throw '只允许本机磁盘路径；不接受 UNC、设备路径或远程资源。' }
    $drive=New-Object IO.DriveInfo ([IO.Path]::GetPathRoot($full))
    if ($drive.DriveType -eq [IO.DriveType]::Network) { throw '拒绝向网络映射盘读写结果或配置。' }
    return $full
}

function Save-Json {
    param([string]$Name,$Value)
    $Value | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $rawDir $Name) -Encoding UTF8
}

function Invoke-ReadGroup {
    param([string]$Name,[string]$Command,[scriptblock]$Query)
    Assert-WindowOpen
    $time=[DateTimeOffset]::Now.ToString('o')
    try {
        $data=@(& $Query)
        $record=[pscustomobject]@{Status='Ok';CollectedAt=$time;Command=$Command;Data=$data;Error=''}
        $data | Export-Clixml -LiteralPath (Join-Path $rawDir ($Name+'.clixml')) -Depth 12
    } catch { $record=[pscustomobject]@{Status='Error';CollectedAt=$time;Command=$Command;Data=@();Error=$_.Exception.Message} }
    Save-Json ($Name+'.json') $record
    return $record
}

function Invoke-NativeRead {
    param([ValidateSet('secedit.exe','auditpol.exe','gpresult.exe')][string]$Name,[string[]]$Arguments,[string]$Tag)
    Assert-WindowOpen
    # Only fixed, built-in queries chosen by the script call this function.
    $exe=Join-Path $env:SystemRoot ('System32\'+$Name)
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        $record=[pscustomobject]@{Status='Error';ExitCode=$null;StdOut='';StdErr='系统自带命令不存在';Command=$Name;CollectedAt=[DateTimeOffset]::Now.ToString('o')}
        Save-Json ($Tag+'.json') $record
        return $record
    }
    $argLine=(@($Arguments | ForEach-Object { '"'+($_ -replace '(\\*)"','$1$1\"' -replace '(\\+)$','$1$1')+'"' }) -join ' ')
    $process=New-Object Diagnostics.Process
    $process.StartInfo=New-Object Diagnostics.ProcessStartInfo
    $process.StartInfo.FileName=$exe; $process.StartInfo.Arguments=$argLine
    $process.StartInfo.UseShellExecute=$false; $process.StartInfo.CreateNoWindow=$true
    $process.StartInfo.RedirectStandardOutput=$true; $process.StartInfo.RedirectStandardError=$true
    $outStream=New-Object IO.MemoryStream; $errStream=New-Object IO.MemoryStream
    try {
        [void]$process.Start()
        $outTask=$process.StandardOutput.BaseStream.CopyToAsync($outStream)
        $errTask=$process.StandardError.BaseStream.CopyToAsync($errStream)
        $timeout=[int][Math]::Min(60000,[Math]::Max(1,($approvedEnd-[DateTimeOffset]::Now).TotalMilliseconds))
        $finished=$process.WaitForExit($timeout)
        if (-not $finished) { $process.Kill(); $process.WaitForExit(); throw "$Name 本次只读子进程超时或运行窗口结束，已停止子进程。" }
        $outTask.GetAwaiter().GetResult(); $errTask.GetAwaiter().GetResult()
        $outBytes=$outStream.ToArray(); $errBytes=$errStream.ToArray()
        [IO.File]::WriteAllBytes((Join-Path $rawDir ($Tag+'.stdout.bin')),$outBytes)
        [IO.File]::WriteAllBytes((Join-Path $rawDir ($Tag+'.stderr.bin')),$errBytes)
        $encoding=[Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
        if ($outBytes.Length -ge 2 -and $outBytes[0] -eq 255 -and $outBytes[1] -eq 254) { $outText=[Text.Encoding]::Unicode.GetString($outBytes) } else { $outText=$encoding.GetString($outBytes) }
        $errText=$encoding.GetString($errBytes)
        $record=[pscustomobject]@{Status=$(if($process.ExitCode -eq 0){'Ok'}else{'Error'});ExitCode=$process.ExitCode;StdOut=$outText;StdErr=$errText;Command=($Name+' '+$argLine);CollectedAt=[DateTimeOffset]::Now.ToString('o')}
        $outText | Set-Content -LiteralPath (Join-Path $rawDir ($Tag+'.txt')) -Encoding UTF8
    } catch { $record=[pscustomobject]@{Status='Error';ExitCode=$null;StdOut='';StdErr=$_.Exception.Message;Command=($Name+' '+$argLine);CollectedAt=[DateTimeOffset]::Now.ToString('o')} }
    finally { $process.Dispose(); $outStream.Dispose(); $errStream.Dispose() }
    Save-Json ($Tag+'.json') $record
    return $record
}

function Get-RegistryBatch {
    param($Items)
    $queries=@{}
    foreach ($item in $Items) {
        if ($item.Applicable -eq 'No' -or $item.Collector -notin @('Registry','DeviceGuard')) { continue }
        foreach ($t in $item.Targets) {
            $id=Get-RegistryId $t
            if (-not $queries.ContainsKey($id)) { $queries[$id]=[pscustomobject]@{Target=$t;BothViews=($item.PolicyPath -like '*Internet Explorer*')} }
            elseif ($item.PolicyPath -like '*Internet Explorer*') { $queries[$id].BothViews=$true }
        }
    }
    $groups=@($queries.Values | Group-Object { $_.Target.Hive+'|'+$_.Target.Key })
    $records=@{}; $view32=@{}
    foreach ($group in $groups) {
        Assert-WindowOpen
        $first=$group.Group[0].Target
        foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)) {
            if ($view -eq [Microsoft.Win32.RegistryView]::Registry32 -and @($group.Group | Where-Object {$_.BothViews}).Count -eq 0) { continue }
            $base=$null; $key=$null
            try {
                $hive=if($first.Hive -eq 'HKLM'){[Microsoft.Win32.RegistryHive]::LocalMachine}else{[Microsoft.Win32.RegistryHive]::CurrentUser}
                $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,$view)
                $key=$base.OpenSubKey([string]$first.Key,$false)
                $names=@(); if($null -ne $key){$names=@($key.GetValueNames())}
                foreach ($q in $group.Group) {
                    if ($view -eq [Microsoft.Win32.RegistryView]::Registry32 -and -not $q.BothViews) { continue }
                    $t=$q.Target; $id=Get-RegistryId $t
                    if ($null -eq $key -or $names -notcontains [string]$t.Name) {
                        $r=[pscustomobject]@{Status='Missing';Hive=$t.Hive;Key=$t.Key;Name=$t.Name;Value=$null;Type='';Error='';View=[string]$view;CollectedAt=[DateTimeOffset]::Now.ToString('o')}
                    } else {
                        $kind=[string]$key.GetValueKind([string]$t.Name)
                        $types=@{DWord='REG_DWORD';QWord='REG_QWORD';String='REG_SZ';ExpandString='REG_EXPAND_SZ';MultiString='REG_MULTI_SZ';Binary='REG_BINARY';None='REG_NONE'}
                        $r=[pscustomobject]@{Status='Ok';Hive=$t.Hive;Key=$t.Key;Name=$t.Name;Value=$key.GetValue([string]$t.Name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);Type=$types[$kind];Error='';View=[string]$view;CollectedAt=[DateTimeOffset]::Now.ToString('o')}
                    }
                    if ($view -eq [Microsoft.Win32.RegistryView]::Registry64) {$records[$id]=$r}else{$view32[$id]=$r}
                }
            } catch {
                foreach ($q in $group.Group) {
                    if ($view -eq [Microsoft.Win32.RegistryView]::Registry32 -and -not $q.BothViews) { continue }
                    $id=Get-RegistryId $q.Target
                    $r=[pscustomobject]@{Status='Error';Hive=$q.Target.Hive;Key=$q.Target.Key;Name=$q.Target.Name;Value=$null;Type='';Error=$_.Exception.Message;View=[string]$view;CollectedAt=[DateTimeOffset]::Now.ToString('o')}
                    if($view -eq [Microsoft.Win32.RegistryView]::Registry64){$records[$id]=$r}else{$view32[$id]=$r}
                }
            } finally {if($null -ne $key){$key.Dispose()};if($null -ne $base){$base.Dispose()}}
        }
    }
    Save-Json 'registry.json' ([pscustomobject]@{View64=$records;View32=$view32;UniqueQueries=$queries.Count;UniqueKeys=$groups.Count;UserScope='当前运行账号 HKCU；不加载其他用户注册表配置单元'})
    [pscustomobject]@{Values=$records;View32=$view32}
}

function Add-RuntimeProperty {
    param([hashtable]$Runtime,$Target,$Group,[string]$Property,[string]$Source,[switch]$BooleanAsInteger,[double]$Scale=1)
    $id=Get-RegistryId $Target
    if ($Group.Status -ne 'Ok' -or @($Group.Data).Count -eq 0) {$Runtime[$id]=[pscustomobject]@{Status='Error';Value=$null;Error=$Group.Error;Source=$Source};return}
    $object=$Group.Data[0]; $p=$object.PSObject.Properties[$Property]
    if ($null -eq $p -or $null -eq $p.Value) {$Runtime[$id]=[pscustomobject]@{Status='Error';Value=$null;Error="有效查询缺少字段 $Property";Source=$Source};return}
    $value=$p.Value
    if ($BooleanAsInteger) { if($value -isnot [bool]){$Runtime[$id]=[pscustomobject]@{Status='Error';Value=$null;Error='有效查询字段不是布尔值';Source=$Source};return};$value=[int]$value }
    elseif($Target.Type -eq 'REG_DWORD'){try{$value=[long]$value}catch{$Runtime[$id]=[pscustomobject]@{Status='Error';Value=$null;Error='有效查询字段无法转为整数';Source=$Source};return}}
    if($Scale -ne 1){$value=[double]$value/$Scale}
    $Runtime[$id]=[pscustomobject]@{Status='Ok';Value=$value;Error='';Source=$Source}
}

function Write-Results {
    param($Snapshot,$Context)
    $rows=New-Object 'System.Collections.Generic.List[object]'
    foreach($item in $manifest.Items) {
        $r=Test-BaselineItem $item $Snapshot
        $viewNotes=New-Object 'System.Collections.Generic.List[string]'
        if ($item.Applicable -eq 'Yes' -and $item.PolicyPath -like '*Internet Explorer*' -and $r.Conclusion -notin @('不适用','不符合')) {
            foreach($t in $item.Targets) {
                $id=Get-RegistryId $t
                if($Snapshot.Registry32.ContainsKey($id)) {
                    $v=Compare-RegistryObservation $t $Snapshot.Registry32[$id]
                    $viewNotes.Add("32 位视图 $($t.Name)=$($v.Current)")
                    if($v.State -eq 'Mismatch'){$r.Conclusion='不符合'}
                    elseif($v.State -eq 'Error' -and $r.Conclusion -ne '不符合'){$r.Conclusion='未检查'}
                    elseif($v.State -eq 'Unknown' -and $r.Conclusion -eq '符合'){$r.Conclusion='待确认'}
                } else {if($r.Conclusion -eq '符合'){$r.Conclusion='待确认'};$viewNotes.Add('32 位视图无本次采集记录')}
            }
        }
        $exceptionNotes=@()
        if($null -ne $Context.PSObject.Properties['Exceptions']) {
            $exceptionNotes=@($Context.Exceptions | Where-Object {$_.ItemId -eq $item.Id} | ForEach-Object {$_ | ConvertTo-Json -Compress -Depth 8})
        }
        $rows.Add([pscustomobject][ordered]@{'主机名'=$identity.ComputerName;'检查时间'=$started.ToString('o');'编号'=$item.Id;'检查项'=$item.Name;'基线要求'=$item.Baseline;'当前值'=$r.Current;'结论'=$r.Conclusion;'采集状态'=$r.CollectionStatus;'证据'=$r.Evidence;'工作表'=$item.Sheet;'行号'=$item.Row;'推荐列'=$item.Column;'判定层次'=$item.EffectScope;'说明'=($r.Note+'；'+($viewNotes -join '；'));'历史差异或例外记录'=($exceptionNotes -join '；')})
    }
    $rows.ToArray() | Export-Csv -LiteralPath (Join-Path $runDir '检查结果.csv') -NoTypeInformation -Encoding UTF8
    $rows.ToArray() | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $runDir '检查结果.json') -Encoding UTF8
    $rows.ToArray() | Where-Object {$_.结论 -in @('未检查','待确认') -or $_.采集状态 -like '*部分*'} | Export-Csv -LiteralPath (Join-Path $runDir '人工复核队列.csv') -NoTypeInformation -Encoding UTF8
    $history=@([pscustomobject]@{类型='环境快照与基线文档差异';编号='';记录='快照 17763.1；官方文档依据 17763.107。不得把较旧构建或历史整改当作已批准例外。';状态='待确认'})
    if($null -ne $Context.PSObject.Properties['Exceptions']){$history+=@($Context.Exceptions | ForEach-Object {[pscustomobject]@{类型='用户单独记录的历史差异或例外';编号=$_.ItemId;记录=($_ | ConvertTo-Json -Compress -Depth 10);状态='只记录；不改写基线或检查结论'}})}
    $history | Export-Csv -LiteralPath (Join-Path $runDir '历史差异与例外.csv') -Encoding UTF8 -NoTypeInformation
    $summary=@('# Windows Server 2019 只读基线检查结果','',('主机：'+$identity.ComputerName),('开始：'+$started.ToString('o')),('结束：'+[DateTimeOffset]::Now.ToString('o')),('基线：'+$manifest.Baseline.Name+'；'+$manifest.Baseline.LastModified+'；'+$manifest.Baseline.SelectedColumn),'','| 结论 | 项数 |','| --- | ---: |')
    foreach($name in @('符合','不符合','不适用','未检查','待确认')){$summary+=('| '+$name+' | '+@($rows | Where-Object {$_.结论 -eq $name}).Count+' |')}
    $summary+=@('','全部 273 条有明确推荐值的 D 列项目均保留在结果表。查询失败和未配置会分别记录，未检查项目不进入符合项。','注册表结果描述当前策略/配置。SMB、Defender、事件日志等有相应有效配置查询时同时核对；审核、LSA 和防火墙使用有效值查询。','VBS/UEFI lock/MAT/启动链、其他用户的用户策略、组件是否实际使用、业务依赖及业务功能仍须人工确认。','仅检查运行账号的 User!D518；不代表全部用户账户覆盖。','本报告未执行业务功能、攻击阻断、端口连通性、云端可用性或重启后生效测试。','查看 人工复核队列.csv、检查结果.csv 的采集状态/判定层次/说明及 raw/ 原始证据。','异常或例外只单独记录，不修改原推荐值，不将不符合改为符合。')
    $summary | Set-Content -LiteralPath (Join-Path $runDir '结果说明.md') -Encoding UTF8
    $hashes=@(Get-ChildItem -LiteralPath $runDir -File -Recurse | ForEach-Object {[pscustomobject]@{文件=$_.FullName.Substring($runDir.Length+1);SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}})
    $hashes | Export-Csv -LiteralPath (Join-Path $runDir '证据文件_SHA256.csv') -NoTypeInformation -Encoding UTF8
}

try {
    $packagePath=Assert-LocalFilePath $PSScriptRoot
    $OutputRoot=Assert-LocalFilePath $OutputRoot
    $RunContextPath=Assert-LocalFilePath $RunContextPath
    Import-Module (Join-Path $packagePath 'Baseline.Core.psm1') -Force
    $manifest=Get-Content -LiteralPath (Join-Path $packagePath 'baseline-manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $runDir=Join-Path $OutputRoot ('检查_'+$started.ToString('yyyyMMdd_HHmmss')+'_'+[Guid]::NewGuid().ToString('N').Substring(0,8))
    $rawDir=Join-Path $runDir 'raw'
    [void](New-Item -ItemType Directory -Path $rawDir -Force)
    if (-not (Test-Path -LiteralPath $RunContextPath -PathType Leaf)) { throw '尚未填写 run-context.json。环境报告不是授权，先审核文件并记录本次本机运行条件。' }
    $context=Get-Content -LiteralPath $RunContextPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $gate=Test-RunContext $context $manifest $started
    Save-Json 'run-context.json' $context
    if (-not $gate.Allowed) { throw ('运行条件未通过：'+($gate.Reasons -join '；')) }
    $approvedEnd=[DateTimeOffset]::Parse($context.ApprovedEnd)
    if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or $PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess -or $ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { throw '本包须在 64 位 Windows PowerShell 5.1 Desktop / FullLanguage 中运行。' }
    $principal=New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw '当前令牌没有管理员权限。停止检查；不会自行提权。' }
    # Identity queries only: no baseline configuration is read before matching.
    Assert-WindowOpen
    $os=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $cs=Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if($null -eq $cs.PSObject.Properties['PartOfDomain'] -or $cs.PartOfDomain -isnot [bool]){throw '未取得可验证的 PartOfDomain 布尔值，停止身份核对。'}
    $currentVersion=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion',$false)
    try {$ubr=$currentVersion.GetValue('UBR',$null);$installation=$currentVersion.GetValue('InstallationType',$null)}finally{if($null -ne $currentVersion){$currentVersion.Dispose()}}
    $identity=[pscustomobject]@{ComputerName=$cs.Name;Caption=$os.Caption;Version=$os.Version;BuildNumber=$os.BuildNumber;ProductType=[int]$os.ProductType;DomainRole=[int]$cs.DomainRole;PartOfDomain=[bool]$cs.PartOfDomain;Domain=$cs.Domain;InstallationType=$installation;UBR=$ubr;Manufacturer=$cs.Manufacturer;Model=$cs.Model;PSVersion=[string]$PSVersionTable.PSVersion;PSEdition=$PSVersionTable.PSEdition;Is64Bit=[Environment]::Is64BitProcess;Admin=$true;RunAccount=[Security.Principal.WindowsIdentity]::GetCurrent().Name;CollectedAt=[DateTimeOffset]::Now.ToString('o')}
    $identity | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $runDir 'identity.json') -Encoding UTF8
    $check=Test-ExpectedIdentity $manifest.ExpectedHost $identity
    if(-not $check.Matches){throw ('目标身份与附件预期不符，停止：'+($check.Reasons -join '；'))}
    if($identity.RunAccount -ine [string]$context.ApprovedRunAccount){throw '当前运行账号与本次确认的 ApprovedRunAccount 不符，停止检查。'}
    if($identity.ProductType -ne 3 -or $identity.DomainRole -ne 2 -or $identity.PartOfDomain -ne $false -or $identity.Version -ne '10.0.17763' -or $identity.Caption -notlike '*Windows Server 2019*' -or $identity.Manufacturer -ne 'VMware, Inc.') { throw '本包仅针对 VMware 中的 Server 2019 独立服务器，拒绝静默改用工作站、域成员或域控范围。' }
    $manifest | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $runDir '本次基线映射.json') -Encoding UTF8
    Write-Host '目标身份匹配。开始本机只读批量采集。'
    $snapshot=@{Registry=@{};Registry32=@{};Runtime=@{};Rights=@{};Audit=@{};Firewall=@{};AccountPolicy=@{};Guest=[pscustomobject]@{Status='Error';Value=$null;Error='尚未查询'};Security=[pscustomobject]@{Status='Error';Values=@{};Error='尚未导出'};ComponentNA=@{}}
    $local=Invoke-NativeRead 'secedit.exe' @('/export','/cfg',(Join-Path $rawDir 'security-local.inf'),'/areas','SECURITYPOLICY','USER_RIGHTS','/log',(Join-Path $rawDir 'secedit-local.log'),'/quiet') 'secedit-local'
    $merged=Invoke-NativeRead 'secedit.exe' @('/export','/mergedpolicy','/cfg',(Join-Path $rawDir 'security-merged.inf'),'/areas','SECURITYPOLICY','USER_RIGHTS','/log',(Join-Path $rawDir 'secedit-merged.log'),'/quiet') 'secedit-merged'
    if($merged.Status -eq 'Ok' -and (Test-Path -LiteralPath (Join-Path $rawDir 'security-merged.inf'))) {
        $inf=ConvertFrom-SecurityInf (Get-Content -LiteralPath (Join-Path $rawDir 'security-merged.inf') -Raw -Encoding Unicode)
        if($inf.Errors.Count -eq 0){$snapshot.Security=[pscustomobject]@{Status='Ok';Values=$inf.Values;Error=''}}else{$snapshot.Security=[pscustomobject]@{Status='Error';Values=@{};Error=($inf.Errors -join '；')}}
    }else{$snapshot.Security=[pscustomobject]@{Status='Error';Values=@{};Error=('secedit 导出失败，ExitCode='+$merged.ExitCode+'；'+$merged.StdErr)}}
    [void](Invoke-NativeRead 'auditpol.exe' @('/get','/subcategory:*','/r') 'auditpol')
    [void](Invoke-NativeRead 'gpresult.exe' @('/scope','computer','/r') 'gpresult-computer')
    [void](Invoke-NativeRead 'gpresult.exe' @('/scope','user','/r') 'gpresult-user')
    $users=Invoke-ReadGroup 'local-users' 'Get-LocalUser (仅本地账号)' {Get-LocalUser -ErrorAction Stop | Select-Object Name,SID,Enabled}
    if($users.Status -eq 'Ok'){
        $guest=@($users.Data | Where-Object {[string]$_.SID -match '^S-1-5-21-.+-501$'})
        if($guest.Count -eq 1){$snapshot.Guest=[pscustomobject]@{Status='Ok';Value=[bool]$guest[0].Enabled;Error=''}}else{$snapshot.Guest=[pscustomobject]@{Status='Error';Value=$null;Error='无法唯一识别 RID 501 的本地账号'}}
    }else{$snapshot.Guest=[pscustomobject]@{Status='Error';Value=$null;Error=$users.Error}}
    $nativeStatus=[pscustomobject]@{Status='Ok';Error='';Note='包装器调用状态；各返回记录另有单项状态与错误码。';CollectedAt=[DateTimeOffset]::Now.ToString('o')}
    try {
        Assert-WindowOpen
        if($null -eq ('BaselineReadOnly.NativeQueries' -as [type])){Add-Type -Path (Join-Path $packagePath 'ReadOnlyNative.cs') -ErrorAction Stop}
        $accountPolicy=@([BaselineReadOnly.NativeQueries]::QueryLocalAccountPolicy())
        foreach($r in $accountPolicy){$snapshot.AccountPolicy[$r.Name]=$r}
        Save-Json 'account-policy-native.json' $accountPolicy
        $rights=@($manifest.Items | Where-Object {$_.Collector -eq 'UserRights' -and $_.Applicable -eq 'Yes'} | ForEach-Object {$_.Targets[0].Name})
        $rightValues=@([BaselineReadOnly.NativeQueries]::QueryRights([string[]]$rights))
        foreach($r in $rightValues){$snapshot.Rights[$r.Name]=$r}
        Save-Json 'lsa-rights.json' $rightValues
        $guids=@($manifest.Items | Where-Object {$_.Collector -eq 'Audit'} | ForEach-Object {$_.Targets[0].Guid})
        $auditValues=@([BaselineReadOnly.NativeQueries]::QueryAudits([string[]]$guids))
        foreach($r in $auditValues){$snapshot.Audit[$r.Name]=$r}
        Save-Json 'audit-native.json' $auditValues
    }catch{
        $nativeError=$_.Exception.Message
        $nativeStatus.Status='Error';$nativeStatus.Error=$nativeError
        Save-Json 'native-query-error.json' ([pscustomobject]@{Status='Error';Error=$nativeError})
        foreach($name in @('MinimumPasswordLength','MaximumPasswordAge','MinimumPasswordAge','PasswordHistorySize','LockoutDuration','ResetLockoutCount','LockoutBadCount')){
            if(-not $snapshot.AccountPolicy.ContainsKey($name)){$snapshot.AccountPolicy[$name]=[pscustomobject]@{Status='Error';Value=$null;Error=$nativeError}}
        }
    }
    Save-Json 'native-query-status.json' $nativeStatus
    $fwActive=Invoke-ReadGroup 'firewall-active' 'Get-NetFirewallProfile -PolicyStore ActiveStore' {Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,PolicyStoreSource,PolicyStoreSourceType}
    [void](Invoke-ReadGroup 'firewall-persistent' 'Get-NetFirewallProfile -PolicyStore PersistentStore' {Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,PolicyStoreSource,PolicyStoreSourceType})
    $fwObject=$null;$fwRows=@()
    try {
        $fwObject=New-Object -ComObject HNetCfg.FwPolicy2
        $fwRows=@(); foreach($pair in @(@('Domain',1),@('Private',2),@('Public',4))) {
            $name=[string]$pair[0];$mask=[int]$pair[1]
            $inAction=[int]$fwObject.DefaultInboundAction($mask);$outAction=[int]$fwObject.DefaultOutboundAction($mask)
            if($inAction -notin @(0,1) -or $outAction -notin @(0,1)){throw '防火墙 API 返回无法识别的默认动作，不作推断。'}
            $props=@{Enabled=[bool]$fwObject.FirewallEnabled($mask);DefaultInboundAction=$(if($inAction -eq 0){'Block'}else{'Allow'});DefaultOutboundAction=$(if($outAction -eq 0){'Block'}else{'Allow'})}
            foreach($prop in $props.Keys){$snapshot.Firewall[$name+'|'+$prop]=[pscustomobject]@{Status='Ok';Value=$props[$prop];Error=''}}
            $fwRows+=[pscustomobject]@{Profile=$name;Mask=$mask;Enabled=$props.Enabled;DefaultInboundAction=$props.DefaultInboundAction;DefaultOutboundAction=$props.DefaultOutboundAction;CurrentlyActive=(([int]$fwObject.CurrentProfileTypes -band $mask) -ne 0)}
        }
        Save-Json 'firewall-effective.json' $fwRows
    }catch{Save-Json 'firewall-effective.json' ([pscustomobject]@{Status='Error';Error=$_.Exception.Message;PartialData=@($fwRows)})}finally{if($null -ne $fwObject){[void][Runtime.InteropServices.Marshal]::ReleaseComObject($fwObject)}}
    $features=Invoke-ReadGroup 'features' 'Get-WindowsFeature (仅本机)' {Get-WindowsFeature -ErrorAction Stop | Select-Object Name,Installed,InstallState}
    $optional=Invoke-ReadGroup 'optional-features' 'Get-WindowsOptionalFeature -Online (本机 DISM 查询)' {Get-WindowsOptionalFeature -Online -ErrorAction Stop | Select-Object FeatureName,State}
    if($optional.Status -eq 'Ok'){
        $ie=@($optional.Data | Where-Object {$_.FeatureName -eq 'Internet-Explorer-Optional-amd64'})
        if($ie.Count -eq 1 -and [string]$ie[0].State -in @('Disabled','DisabledWithPayloadRemoved')){
            foreach($it in $manifest.Items | Where-Object {$_.PolicyPath -like '*Internet Explorer*'}){$snapshot.ComponentNA[$it.Id]='本次本机可选功能查询明确显示 IE 可选功能未启用；保留原要求。将来启用后须重新检查。'}
        }
    }
    $regItems=@($manifest.Items | Where-Object {-not $snapshot.ComponentNA.ContainsKey($_.Id)})
    $reg=Get-RegistryBatch $regItems
    $snapshot.Registry=$reg.Values;$snapshot.Registry32=$reg.View32
    $smbClient=Invoke-ReadGroup 'smb-client' 'Get-SmbClientConfiguration' {Get-SmbClientConfiguration -ErrorAction Stop}
    $smbServer=Invoke-ReadGroup 'smb-server' 'Get-SmbServerConfiguration' {Get-SmbServerConfiguration -ErrorAction Stop}
    $mpPref=Invoke-ReadGroup 'defender-preference' 'Get-MpPreference' {Get-MpPreference -ErrorAction Stop}
    $mpStatus=Invoke-ReadGroup 'defender-status' 'Get-MpComputerStatus' {Get-MpComputerStatus -ErrorAction Stop}
    $snapshot.MpStatus=$mpStatus
    $services=Invoke-ReadGroup 'selected-services' 'Win32_Service 本机选定服务状态' {Get-CimInstance -ClassName Win32_Service -Filter "Name='WinRM' OR Name='WinDefend' OR Name='mpssvc' OR Name='BFE' OR Name='LanmanServer' OR Name='LanmanWorkstation' OR Name='TermService'" -ErrorAction Stop | Select-Object Name,State,StartMode}
    $snapshot.Services=$services
    # WSMan provider reads only the explicit localhost configuration. No remote target parameter.
    $wsman=Invoke-ReadGroup 'winrm-effective' 'WSMan:\localhost 的 Client/Service 本机有效配置' {
        $localWinRM=@($services.Data | Where-Object {$_.Name -eq 'WinRM'})
        if($services.Status -ne 'Ok' -or $localWinRM.Count -ne 1 -or $localWinRM[0].State -ne 'Running'){throw 'WinRM 服务未明确处于运行状态；跳过 WSMan 有效值查询，不启动服务。'}
        foreach($path in @('Client\Auth\Basic','Client\AllowUnencrypted','Client\Auth\Digest','Service\Auth\Basic','Service\AllowUnencrypted','Service\DisableRunAs')){
            try{$v=Get-Item -LiteralPath ('WSMan:\localhost\'+$path) -ErrorAction Stop;[pscustomobject]@{Path=$path;Status='Ok';Value=$v.Value;Error=''}}
            catch{[pscustomobject]@{Path=$path;Status='Error';Value=$null;Error=$_.Exception.Message}}
        }
    }
    $eventLogs=Invoke-ReadGroup 'eventlog-config' 'Get-WinEvent -ListLog Application,Security,System (只读日志配置，不读事件正文)' {Get-WinEvent -ListLog Application,Security,System -ErrorAction Stop | Select-Object LogName,MaximumSizeInBytes,IsEnabled,LogMode}
    $dg=Invoke-ReadGroup 'deviceguard' 'Win32_DeviceGuard（本机 CIM）' {Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop}
    $snapshot.DeviceGuard=$dg
    [void](Invoke-ReadGroup 'secureboot' 'Confirm-SecureBootUEFI（本机只读）' {Confirm-SecureBootUEFI -ErrorAction Stop})
    $mpMap=@{2281='PUAProtection';2299='MAPSReporting';2300='SubmitSamplesConsent';2318='DisableBehaviorMonitoring';2346='DisableRemovableDriveScanning';2358='DisableEmailScanning';2384='EnableNetworkProtection'}
    $wsMap=@{2480='Client\Auth\Basic';2482='Client\AllowUnencrypted';2483='Client\Auth\Digest';2487='Service\Auth\Basic';2490='Service\AllowUnencrypted';2493='Service\DisableRunAs'}
    foreach($it in $manifest.Items) {
        if($it.Applicable -ne 'Yes' -or $it.Collector -ne 'Registry'){continue}
        if($it.Sheet -eq 'Security Template' -and $it.Row -in @(76,78)) {Add-RuntimeProperty $snapshot.Runtime $it.Targets[0] $smbClient $it.Targets[0].Name 'Get-SmbClientConfiguration' -BooleanAsInteger}
        if($it.Sheet -eq 'Security Template' -and $it.Row -eq 81) {Add-RuntimeProperty $snapshot.Runtime $it.Targets[0] $smbServer 'RequireSecuritySignature' 'Get-SmbServerConfiguration' -BooleanAsInteger}
        if($it.Sheet -eq 'Computer' -and $it.Row -eq 26) {Add-RuntimeProperty $snapshot.Runtime $it.Targets[0] $smbServer 'EnableSMB1Protocol' 'Get-SmbServerConfiguration' -BooleanAsInteger}
        if($it.Sheet -eq 'Computer' -and $mpMap.ContainsKey([int]$it.Row)) {Add-RuntimeProperty $snapshot.Runtime $it.Targets[0] $mpPref $mpMap[[int]$it.Row] 'Get-MpPreference' -BooleanAsInteger:($it.Row -in @(2318,2346,2358))}
        if($it.Sheet -eq 'Computer' -and $wsMap.ContainsKey([int]$it.Row)){
            $values=@($wsman.Data | Where-Object {$_.Path -eq $wsMap[[int]$it.Row]})
            $id=Get-RegistryId $it.Targets[0];$b=$false
            if($values.Count -eq 1 -and $values[0].Status -eq 'Ok' -and [bool]::TryParse([string]$values[0].Value,[ref]$b)){$snapshot.Runtime[$id]=[pscustomobject]@{Status='Ok';Value=[int]$b;Error='';Source=('WSMan:\localhost\'+$wsMap[[int]$it.Row])}}
            else{$snapshot.Runtime[$id]=[pscustomobject]@{Status='Error';Value=$null;Error='本机 WSMan 有效配置未取得或布尔值无效';Source=('WSMan:\localhost\'+$wsMap[[int]$it.Row])}}
        }
        if($it.Sheet -eq 'Computer' -and $it.Row -in @(973,979,992)) {
            $logName=@{973='Application';979='Security';992='System'}[[int]$it.Row]
            $data=@($eventLogs.Data | Where-Object {$_.LogName -eq $logName})
            $group=[pscustomobject]@{Status=$eventLogs.Status;Data=$data;Error=$eventLogs.Error}
            Add-RuntimeProperty $snapshot.Runtime $it.Targets[0] $group 'MaximumSizeInBytes' 'Get-WinEvent -ListLog；bytes/1024' -Scale 1024
        }
    }
    # ASR effective rule actions: GUID lookup, never positional assumptions or locale text.
    $asr=@($manifest.Items | Where-Object {$_.Sheet -eq 'Computer' -and $_.Row -eq 2379})[0]
    if($mpPref.Status -eq 'Ok' -and $mpPref.Data.Count -eq 1) {
        $p=$mpPref.Data[0];$idsProp=$p.PSObject.Properties['AttackSurfaceReductionRules_Ids'];$actionsProp=$p.PSObject.Properties['AttackSurfaceReductionRules_Actions']
        if($null -ne $idsProp -and $null -ne $actionsProp) {
            $ids=@($idsProp.Value);$actions=@($actionsProp.Value)
            foreach($target in $asr.Targets | Where-Object {$_.Name -match '^[0-9a-f-]{36}$'}) {
                $hits=@();for($j=0;$j -lt $ids.Count;$j++){if([string]$ids[$j] -ieq [string]$target.Name){$hits+= $j}}
                if($hits.Count -eq 1 -and $ids.Count -eq $actions.Count){$snapshot.Runtime[(Get-RegistryId $target)]=[pscustomobject]@{Status='Ok';Value=[string]$actions[$hits[0]];Error='';Source='Get-MpPreference ASR GUID/action'}}
                else{$snapshot.Runtime[(Get-RegistryId $target)]=[pscustomobject]@{Status='Error';Value=$null;Error='该 GUID 没有唯一有效动作或数组不一致';Source='Get-MpPreference ASR GUID/action'}}
            }
        }
    }
    Save-Json 'runtime.json' $snapshot.Runtime
    $snapshot | Export-Clixml -LiteralPath (Join-Path $rawDir 'normalized-snapshot.clixml') -Depth 30
    Write-Results $snapshot $context
    Write-Host ('已保存：'+$runDir)
    Write-Host '查看检查结果.csv、人工复核队列.csv、结果说明.md 及 raw/ 证据。配置符合不代表业务功能测试通过。'
} catch {
    $reason=$_.Exception.Message
    if($null -ne $runDir){
        @('启动或检查已停止。',('时间：'+[DateTimeOffset]::Now.ToString('o')),('原因：'+$reason),'如尚未通过身份核对，本次没有开始基线配置采集；不静默改用其他列。','如批量采集或结果写入中断，raw/ 仅为部分证据，不能据此宣称检查完成。') | Set-Content -LiteralPath (Join-Path $runDir '停止原因.txt') -Encoding UTF8
    }
    Write-Error ('检查停止：'+$reason) -ErrorAction Continue
    exit 2
}
