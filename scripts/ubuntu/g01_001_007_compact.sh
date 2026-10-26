#!/usr/bin/env bash
# G01-001～007：简明批量检查。仅由用户在目标Ubuntu运行。
# 不执行 sshd、ssh-keygen、file，不读取任何主机密钥的内容。
# 终端/结果TXT显示逐项摘要；证据TXT保留输出、错误及退出码。
if [[ ${BASH_SOURCE[0]} != "$0" ]]; then
    printf '请用 bash 运行本文件，不要 source。\n' >&2
    return 2
fi
set +e
set -u
set -o pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
export SYSTEMD_PAGER=cat SYSTEMD_COLORS=0
unset DBUS_SYSTEM_BUS_ADDRESS DBUS_SESSION_BUS_ADDRESS SYSTEMD_BUS_ADDRESS SYSTEMD_HOST SYSTEMD_MACHINE

# 一、保存、时间戳及错误处理；与下方核心取证命令分开。
umask 077
for tool in date mktemp; do
    if ! type -P "$tool" >/dev/null 2>&1; then
        printf '无法创建报告：缺少 %s；停止，不安装工具。\n' "$tool" >&2
        exit 2
    fi
done
stamp=$(date '+%Y%m%d_%H%M%S') || exit 2
report=$(mktemp "./G01_001_007_证据_${stamp}_XXXXXX.txt") || {
    printf '报告创建失败；当前目录可能不可写。停止，不提权。\n' >&2
    exit 2
}
exec 3>"$report" || exit 2
summary=$(mktemp "./G01_001_007_结果_${stamp}_XXXXXX.txt") || exit 2
exec 4>"$summary" || exit 2
result() {
    printf '%s\n' "$*"
    if ! printf '%s\n' "$*" >&4; then
        printf '结果写入失败，请保留终端输出及证据文件。\n' >&2
        exit 2
    fi
}
printf '若无末尾采集结束说明，本次记录不完整。\n' >&4
q=0 gaps=0 rc=0 out=''
emit() {
    if ! printf '%s\n' "$*" >&3; then
        printf '报告写入失败，内容可能不完整：%s\n' "$report" >&2
        exit 2
    fi
}
gap() { gaps=$((gaps+1)); emit "[信息缺口] $*"; }
stop_report() {
    emit "停止原因：$*"
    emit '本批未完成；没有基线结论。'
    printf '已停止。报告：%s/%s\n' "$PWD" "${report#./}"
    exit 2
}
trap 'emit "用户中断；报告不完整。"; result "采集已中断，本次结果不完整。"; exit 130' INT TERM HUP
run() {
    local title=$1 rendered
    shift
    q=$((q+1))
    printf -v rendered '%q ' "$@"
    emit ''
    emit "[E-$q] $title"
    emit "命令：${rendered% }"
    if ! type -P "$1" >/dev/null 2>&1; then
        out="命令不存在：$1"; rc=127
    elif type -P timeout >/dev/null 2>&1; then
        out=$(timeout --kill-after=2s 10s "$@" 2>&1); rc=$?
    else
        out=$("$@" 2>&1); rc=$?
    fi
    emit '标准输出与标准错误（合并保留）：'
    emit "${out:-（空输出）}"
    emit "退出码：$rc"
    if [[ $1 == grep && $rc == 1 ]]; then
        emit "状态：无匹配（grep退出码1），不是查询故障。"
    elif (( rc == 127 )); then
        gap '命令缺失或无法执行，未取得证据。'
    elif (( rc == 124 || rc == 137 )); then
        gap '查询超时或被终止，证据不完整。'
    elif (( rc != 0 )); then
        case "$out" in
            *'Permission denied'*|*'Access denied'*|*'Operation not permitted'*) gap '权限不足；不提权，不重试绕过。' ;;
            *) gap '查询失败；不能当作文件不存在或符合。' ;;
        esac
    else
        emit '状态：查询结束；退出码为 0 不等于检查项符合。'
    fi
}

# 同一次运行中，同一完整路径只查询一次；保留首次记录编号和成功/失败状态。
declare -A local_path_status=() local_path_evidence=()
# 仅读取已确认处于本地文件系统的路径；不自动接触远程挂载。
local_path() {
    local path=$1 status=1
    if [[ ${local_path_status[$path]+known} ]]; then
        emit "文件系统查询复用：[E-${local_path_evidence[$path]}]，路径：$path；不重复执行。"
        return "${local_path_status[$path]}"
    fi
    run "确认路径所在文件系统：$1" findmnt -rn --nocanonicalize -T "$1" -o FSTYPE
    local_path_evidence[$path]=$q
    if (( rc != 0 )); then
        gap "未确认本地文件系统，跳过路径：$1"
    else
        case "$out" in
            ext2|ext3|ext4|xfs|btrfs|tmpfs|overlay|zfs) status=0 ;;
            *) gap "文件系统类型未在本地白名单内（${out:-空}），跳过路径：$1" ;;
        esac
    fi
    local_path_status[$path]=$status
    return "$status"
}
# 二、判定与简短输出。这里不执行加固，不读取任何密钥内容。
names=('' '远程提示内容' '提示文件权限' 'SSH配置权限' '主机私钥权限' '主机公钥权限' '用户/组访问限制' 'SSH登录前Banner')
rules=('' '无系统信息标记，文案符合策略' 'root:root；不宽于0644' 'root:root；不宽于0600' 'root所有；root组不宽于0600，确认专用组后可0640' 'root:root；不宽于0644' '至少一种符合本地策略的用户/组访问名单' 'Banner为绝对路径，文案符合要求')
declare -A verdict=() actual=() reason=()
for i in {1..7}; do verdict[$i]='未检查'; actual[$i]='未取得证据'; reason[$i]=''; done
set_row() { verdict[$1]=$2; actual[$1]=$3; reason[$1]=${4:-}; }
show_results() {
    local i
    result 'G01-001～007｜SSH登录检查（配置层面）'
    result "采集时间：$stamp；依据：CIS Ubuntu 20.04 v3.0.0 / Level 1 Server"
    for i in {1..7}; do
        result ''
        result "[G01-$(printf '%03d' "$i")] ${verdict[$i]} | ${names[$i]}"
        result "  推荐：${rules[$i]}"
        result "  实际：${actual[$i]}"
        [[ -z ${reason[$i]} ]] || result "  说明：${reason[$i]}"
    done
    result ''
    result '所列文件符合不等于全部文件已覆盖；不代表整组22项完成。'
    result '本脚本不统计人工复核、整改或整改复测次数；按实际工作记录另行汇总。'
    result "详细证据：$PWD/${report#./}"
    printf '\n简明结果：%s/%s\n' "$PWD" "${summary#./}"
}
stop_report() {
    emit "停止原因：$*"
    for i in {1..7}; do set_row "$i" '未检查' "$*" '已停止，不套用当前基线'; done
    show_results
    exit 2
}

# stat只取元数据；成功与失败都保存到证据TXT。
file_check() {
    local path=$1 kind=$2 bits allowed type mode uid gid
    fstate='待核实'; fact="$path：未检查"; f_signature=''
    local_path "$path" || { fact="$path：本地路径未确认"; return; }
    run "元数据：$path" stat -c '%F|%a|%u|%g' -- "$path"
    if (( rc != 0 )); then fstate='采集失败'; fact="$path：查询失败，见E-$q"; return; fi
    IFS='|' read -r type mode uid gid <<< "$out"
    if [[ $type != 'regular file' || ! $mode =~ ^[0-7]{1,4}$ || ! $uid =~ ^[0-9]+$ || ! $gid =~ ^[0-9]+$ ]]; then
        fact="$path：类型或格式待核对，见E-$q"; return
    fi
    bits=$((8#$mode))
    allowed=$((8#644)); [[ $kind != config && $kind != private ]] || allowed=$((8#600))
    [[ $kind != private || $gid == 0 ]] || allowed=$((8#640))
    printf -v mode '%04o' "$bits"
    fact="$path：$mode UID=$uid/GID=$gid"
    f_signature="$mode UID=$uid/GID=$gid"
    fstate='符合'
    if [[ $uid != 0 ]] || (( (bits & (07777 ^ allowed)) != 0 )); then
        fstate='不符合'
    elif [[ $gid != 0 ]]; then
        if [[ $kind == private ]]; then fstate='待核实'; fact+='（专用组未确认）'; else fstate='不符合'; fi
    fi
    emit "文件判断：$fstate；$fact"
}
check_files() {
    local index=$1 kind=$2 p count=0 good=0 bad=0 unsure=0 failed=0 modes='' detail=''
    local -A seen_modes=()
    shift 2
    for p in "$@"; do
        count=$((count+1))
        if (( count > 64 )); then unsure=$((unsure+1)); count=64; detail+='超出64个上限；'; break; fi
        file_check "$p" "$kind"
        if [[ -n $f_signature && ! ${seen_modes[$f_signature]+known} ]]; then
            modes+="$f_signature；"; seen_modes[$f_signature]=1
        fi
        case "$fstate" in
            符合) good=$((good+1)) ;;
            不符合) bad=$((bad+1)); detail+="$fact；" ;;
            采集失败) failed=$((failed+1)); detail+="$fact；" ;;
            *) unsure=$((unsure+1)); detail+="$fact；" ;;
        esac
    done
    if (( count == 0 )); then
        set_row "$index" '待核实' '未取得候选文件' '不能据此认定文件或组件不存在'
    elif (( bad > 0 )); then
        set_row "$index" '不符合（已查文件）' "$count个：$good符合/$bad不符合/$failed失败/$unsure待核实" "$detail"
    elif (( failed > 0 )); then
        set_row "$index" '采集失败' "$count个：$good符合/$failed失败/$unsure待核实" "$detail"
    elif (( unsure > 0 )); then
        set_row "$index" '待核实' "$count个：$good符合/$unsure待核实" "$detail"
    else
        set_row "$index" '符合（已查文件）' "$count个文件；$modes" '完整文件范围仍需核对'
    fi
}

# 三、核心只读查询。每个配置文件只读取一次，共用结果判断006/007。
if ! type -P timeout >/dev/null 2>&1; then
    emit 'timeout不存在：本次无单条查询超时保护；不安装工具，卡住时可按Ctrl+C。'
fi
run '时间' date '+%Y-%m-%d %H:%M:%S %z'
run '资产核对' uname -s -n -r -m
[[ $rc == 0 && $out == 'Linux lab-ubuntu20 5.4.0-216-generic x86_64' ]] || stop_report '资产身份与原环境报告不同或查询失败'
run '发行版本' awk '/^(ID|VERSION_ID)=/ {print}' /etc/os-release
[[ $rc == 0 && "$out" =~ (^|$'\n')ID=\"?ubuntu\"?($|$'\n') && "$out" =~ (^|$'\n')VERSION_ID=\"?20\.04\"?($|$'\n') ]] || stop_report '未确认Ubuntu 20.04'
[[ ! -L /etc && ! -L /etc/ssh ]] || stop_report '配置目录是符号链接，需要先核对实际位置'
local_path /etc/ssh || stop_report 'SSH目录本地文件系统未确认'

if local_path /etc/issue.net && [[ ! -L /etc/issue.net && -f /etc/issue.net ]]; then
    run 'G01-001 提示标记（只输出匹配标记）' grep -Eo '\\[vrms]|[Uu][Bb][Uu][Nn][Tt][Uu]' -- /etc/issue.net
    case $rc in
        0) set_row 1 '不符合' "检出 ${out//$'\n'/、}" '提示文件含系统信息标记' ;;
        1) set_row 1 '待人工确认' '未检出所查系统信息标记' '还需确认文案符合本地策略' ;;
        *) set_row 1 '采集失败' "退出码=$rc，见E-$q" ;;
    esac
else
    set_row 1 '待核实' '提示文件不是已确认本地普通文件'
fi
check_files 2 banner /etc/issue.net
if [[ ${verdict[2]} == '符合（已查文件）' ]]; then
    set_row 2 '符合' "$fact"
fi

cfg_complete=1
configs=(/etc/ssh/sshd_config)
shopt -s nullglob
if local_path /etc/ssh/sshd_config.d && [[ ! -L /etc/ssh/sshd_config.d && -d /etc/ssh/sshd_config.d && -r /etc/ssh/sshd_config.d && -x /etc/ssh/sshd_config.d ]]; then
    configs+=(/etc/ssh/sshd_config.d/*.conf)
else
    cfg_complete=0
    emit '配置片段目录未确认可访问；006/007不能作确定结论。'
fi
check_files 3 config "${configs[@]}"
access='' banners='' includes=0
config_count=0
for p in "${configs[@]}"; do
    config_count=$((config_count+1))
    if (( config_count > 64 )); then cfg_complete=0; break; fi
    if ! local_path "$p" || [[ -L $p || ! -f $p ]]; then cfg_complete=0; continue; fi
    run "006/007 必要声明：$p" awk '
      { line=$0; sub(/#.*/, "", line); sub(/^[ \t]+/, "", line)
        key=line; sub(/[ \t=].*$/, "", key); key=tolower(key)
        if(key ~ /^(include|match|banner|allowusers|allowgroups|denyusers|denygroups)$/) {
          value=line; sub(/^[^ \t=]+[ \t=]+/, "", value); sub(/[ \t]+$/, "", value)
          print key "|" value "|" FNR
        }
      }' "$p"
    if (( rc != 0 )); then cfg_complete=0; continue; fi
    while IFS='|' read -r key value line; do
        case "$key" in
            include)
                if [[ $p == /etc/ssh/sshd_config && $value == '/etc/ssh/sshd_config.d/*.conf' ]]; then
                    includes=$((includes+1))
                else cfg_complete=0; fi ;;
            match) cfg_complete=0 ;;
            banner) banners+="$value（${p##*/}:$line）；" ;;
            allowusers|allowgroups|denyusers|denygroups) access+="$key=$value（${p##*/}:$line）；" ;;
        esac
    done <<< "$out"
done
(( includes == 1 )) || cfg_complete=0
check_files 4 private /etc/ssh/ssh_host_*_key
check_files 5 public /etc/ssh/ssh_host_*_key.pub

# 静态启动文件只输出是否匹配，不导出启动参数或完整进程命令行。
start_ok=0 unit_ok=0 opts_ok=0 manager_ok=0
run 'SSH单元来源' systemctl --system --no-pager show --property=LoadState,FragmentPath,DropInPaths -- ssh.service
if (( rc == 0 )) && [[ $out == *'LoadState=loaded'* && $out == *'FragmentPath=/lib/systemd/system/ssh.service'* ]] && [[ "$out" =~ (^|$'\n')DropInPaths=($|$'\n') ]]; then manager_ok=1; fi
if local_path /lib/systemd/system/ssh.service && [[ ! -L /lib/systemd/system/ssh.service && -f /lib/systemd/system/ssh.service ]]; then
    run 'SSH启动入口分类' awk '
      /^[ \t]*ExecStart[ \t]*=/ { n++; if($0=="ExecStart=/usr/sbin/sshd -D $SSHD_OPTS") ok++ }
      /^[ \t]*EnvironmentFile[ \t]*=/ { e++; if($0=="EnvironmentFile=-/etc/default/ssh") eo++ }
      /^[ \t]*(Environment|PassEnvironment|UnsetEnvironment|RootDirectory|RootImage)[ \t]*=/ { other++ }
      END { print (n==1 && ok==1 && e==1 && eo==1 && !other) ? "standard" : "review" }
    ' /lib/systemd/system/ssh.service
    [[ $rc == 0 && $out == standard ]] && unit_ok=1
fi
if local_path /etc/default/ssh && [[ ! -L /etc/default/ssh && -f /etc/default/ssh ]]; then
    run 'SSHD_OPTS空值分类' awk '
      /^[ \t]*SSHD_OPTS[ \t]*=/ {
        n++; v=$0; sub(/^[^=]*=/,"",v); gsub(/^[ \t]+|[ \t]+$/,"",v)
        if(v=="" || v=="\"\"" || v=="\047\047") empty++
      }
      /^[ \t]*[^# \t]/ && !/^[ \t]*SSHD_OPTS[ \t]*=/ { other++ }
      END { print (n==1 && empty==1 && !other) ? "empty" : "review" }
    ' /etc/default/ssh
    [[ $rc == 0 && $out == empty ]] && opts_ok=1
fi
(( manager_ok && unit_ok && opts_ok )) && start_ok=1
if [[ -n $access ]]; then
    set_row 6 '待人工确认' "$access" '核对名单是否符合本地策略；条件配置另行核对'
elif (( cfg_complete && start_ok )); then
    set_row 6 '不符合（已核查配置）' '未配置用户/组访问名单' '默认配置入口已核对；未进行登录测试'
else
    set_row 6 '待核实' '已查配置未见用户/组访问名单' '配置覆盖或启动入口尚未完整确认；见证据'
fi
if [[ -n $banners ]]; then
    set_row 7 '待人工确认' "Banner声明：$banners" '需核对实际适用路径及文案；本批不自动打开自定义路径'
elif (( cfg_complete && start_ok )); then
    set_row 7 '不符合（已核查配置）' '未设置Banner；标准入口，额外参数为空' '原文默认不显示Banner；未进行登录测试'
else
    set_row 7 '待核实' '已查配置未见Banner' '配置覆盖或启动入口尚未完整确认；见证据'
fi
emit '本批采集完成；无加固操作。'
show_results

result "本批采集结束。仅覆盖G01-001～007；人工复核另行记录。"
