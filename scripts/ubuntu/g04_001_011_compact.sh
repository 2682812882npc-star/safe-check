#!/usr/bin/env bash
if [[ ! -x /usr/bin/python3 ]]; then
  printf '%s\n' '缺少/usr/bin/python3，未执行检查；不自动安装。' >&2
  exit 127
fi
/usr/bin/python3 -I - <<'G04_PY'
import gzip
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile
from datetime import datetime





import ipaddress
import shutil

ITEMS = [
 (1,'监听服务与端口','2.1.22','260–261','监听服务、地址和端口均经本地策略批准'),
 (2,'IPv6状态识别','3.1.1','327–328','明确IPv6状态；启用时覆盖IPv6规则，不强制禁用'),
 (3,'单一防火墙管理工具','4.1.1','415–416','使用一套防火墙管理工具，避免管理服务冲突'),
 (4,'UFW安装','4.2.1','419–420','使用UFW方案时应安装ufw'),
 (5,'UFW与nftables服务互斥','4.2.2','421–422','nftables未安装，或其服务既未启用也未运行'),
 (6,'UFW与持久化工具互斥','4.2.3','423–424','使用UFW时不安装iptables-persistent'),
 (7,'UFW启用状态','4.2.4','425–426','服务enabled、active，且ufw状态active'),
 (8,'UFW回环流量','4.2.5','428–429','允许lo流量；拒绝非lo来源的127.0.0.0/8，IPv6适用时含::1'),
 (9,'UFW出站规则','4.2.6','430–431','新建出站连接规则符合本地业务策略'),
 (10,'UFW端口规则覆盖','4.2.7','432–433','非回环监听端口均有规则，区分协议、地址、来源及IPv4/IPv6'),
 (11,'UFW默认策略','4.2.8','435–436','incoming、outgoing、routed均为deny/reject/disabled'),
]


def short(values):
    return '；'.join(values[:8])+('；另{}条见证据'.format(len(values)-8) if len(values)>8 else '')


def listeners(text):
    rows=[]
    for line in text.splitlines():
        fields=line.split()
        if len(fields)<6 or fields[0] not in ('tcp','udp'):
            raise ValueError('ss输出结构异常，未按空监听判断')
        endpoint=fields[4]
        address, port=endpoint.rsplit(':',1)
        if not port.isdigit(): raise ValueError('ss端口不是数字')
        host=address.strip('[]').split('%',1)[0]
        loopback=False
        if host!='*':
            loopback=ipaddress.ip_address(host).is_loopback
        rows.append((fields[0],endpoint,loopback))
    return rows


def ipv6_result(module, values, errors):
    if module=='1':
        return ('符合（状态已识别）','IPv6模块disable=1','仅确认状态，不评价全部IPv6安全配置'),False
    if module!='0' or errors or not values or any(v not in ('0','1') for v in values.values()):
        return ('待核实','IPv6参数未完整取得','不能把文件缺失或查询失败当成IPv6已禁用'),None
    disabled=all(v=='1' for v in values.values())
    state='全部所查接口及all/default均disable_ipv6=1' if disabled else 'IPv6未全局禁用；至少一个接口或all/default为0'
    return ('符合（状态已识别）',state,'仅确认状态；接口名单和数值见证据'),not disabled


def unit_parse(output,rc):
    if rc: return None
    fields=dict(line.split('=',1) for line in output.splitlines() if '=' in line)
    if not {'LoadState','ActiveState','UnitFileState'}.issubset(fields): return None
    if fields['LoadState'] not in ('loaded','not-found','masked'): return None
    return fields


def active(unit):
    return unit is not None and unit['ActiveState']=='active'


def enabled(unit):
    return unit is not None and unit['UnitFileState'] in ('enabled','enabled-runtime')


def ufw_state(text,rc):
    if rc: return None
    match=re.search(r'^Status: (active|inactive)\s*$',text,re.M)
    return match[1] if match else None


def default_result(text,rc):
    if rc: return '待核实','UFW状态查询失败','错误见证据'
    if ufw_state(text,rc)=='inactive':
        return '不符合','UFW为inactive，未取得生效默认策略','不把配置文件声明当成当前保护'
    found=re.search(r'^Default:\s*(\w+) \(incoming\),\s*(\w+) \(outgoing\),\s*(\w+) \(routed\)',text,re.M)
    if not found: return '待核实','未取得完整三方向默认策略','不推定默认值'
    vals=found.groups()
    return ('符合' if all(v in ('deny','reject','disabled') for v in vals) else '不符合',
            '入站={}；出站={}；转发={}'.format(*vals),'按原文三方向核对；出站allow不满足本条')


def clean_rules(text):
    # 保存结构化白名单；不保存任意comment、LOG前缀或payload匹配字符串。
    rows=[]
    keep={'-A','-p','-s','-d','-i','-o','-j','-g','--sport','--dport','--sports','--dports',
          '--to-destination','--to-source','--ctstate','--state','--reject-with','-m'}
    for line in text.splitlines():
        if line.startswith('*') or line.startswith(':'):
            rows.append(line)
        elif line.startswith('-A '):
            parts=shlex.split(line); out=[]; i=0
            while i<len(parts):
                if parts[i] in keep and i+1<len(parts):
                    if parts[i]=='-m' and parts[i+1] in ('comment','string'):
                        i+=2; continue
                    out.extend(parts[i:i+2]); i+=2
                elif parts[i]=='!': out.append('!'); i+=1
                else:
                    # 不认识的匹配条件必须留下标记，不能把过滤后的规则视为无条件。
                    if parts[i]=='--comment' and i+1<len(parts): i+=2
                    else:
                        out.append('[其他条件已省略]'); i+=1
                        if i<len(parts) and not parts[i].startswith('-'): i+=1
            rows.append(shlex.join(out))
    return '\n'.join(rows)


def loopback_result(configs,text,status,ipv6,rule_ok):
    if status!='active':
        return ('不符合','UFW为inactive','未形成UFW保护') if status=='inactive' else ('待核实','未确认UFW状态','错误见证据')
    if ipv6 is None or not rule_ok or configs.get(4) is None or (ipv6 and configs.get(6) is None):
        return '待核实','回环配置、运行规则或IPv6范围未完整取得','不能仅凭部分匹配判为符合'
    missing=[]
    for family in ([4,6] if ipv6 else [4]):
        prefix='ufw6' if family==6 else 'ufw'
        lines={line.split('#',1)[0].strip() for line in configs[family].splitlines()}
        for rule in ('-A '+prefix+'-before-input -i lo -j ACCEPT','-A '+prefix+'-before-output -o lo -j ACCEPT'):
            if rule not in lines: missing.append('IPv{}未见标准lo放行声明'.format(family)); break
    if not re.search(r'^Anywhere\s+DENY IN\s+127\.0\.0\.0/8\s*$',text,re.M):
        missing.append('未见127.0.0.0/8的标准DENY IN规则')
    if ipv6 and not re.search(r'^Anywhere \(v6\)\s+DENY IN\s+::1(?:/128)?\s*$',text,re.M):
        missing.append('未见::1的标准DENY IN规则')
    # 其他等效写法及规则顺序需要人工读证据，不能因未匹配模板直接判不符合。
    if missing: return '待核实',short(missing),'需对照证据确认缺失还是等效规则写法'
    return '待核实','原文要求的lo放行及回环来源拒绝声明均已找到','运行规则已采集；需确认链调用及规则先后顺序'

def main():
    if sys.platform != 'linux':
        raise SystemExit('仅在目标Ubuntu运行；未执行任何采集。')
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['LC_ALL'] = 'C'
    os.umask(0o077)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    fd, proof_name = tempfile.mkstemp(prefix='G04_001_011_证据_' + stamp + '_', suffix='.txt', dir='.')
    proof = os.fdopen(fd, 'w', encoding='utf-8', buffering=1)
    q = 0

    def log(title, output, rc):
        nonlocal q
        q += 1
        proof.write('[E-{}] {}\n输出与错误：\n{}\n退出码/读取状态码：{}\n\n'.format(q, title, output, rc))
        return q

    def run(args, transform=None):
        try:
            p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, encoding='utf-8', errors='replace', timeout=10)
            output, rc = p.stdout, p.returncode
        except subprocess.TimeoutExpired as exc:
            output = '查询超时；本条输出不完整，未据此判断符合'
            rc = 124
        except FileNotFoundError:
            output, rc = '命令不存在：' + args[0], 127
        except OSError as exc:
            output, rc = str(exc), 1
        if transform is not None and rc == 0:
            try:
                output = transform(output)
            except (ValueError, TypeError) as exc:
                output, rc = '安全字段转换失败：' + str(exc), 65
        log('命令：' + shlex.join(args), output, rc)
        return output.strip(), rc

    def safe_file(path, directory=False):
        # 先只查挂载表，再读取已确认本地路径；不跟随路径上的符号链接。
        fs, rc = run(['findmnt', '-rn', '--nocanonicalize', '-T', str(path), '-o', 'FSTYPE'])
        if rc or fs not in ('ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'tmpfs', 'overlay', 'zfs'):
            raise OSError('未确认本地文件系统：' + str(path))
        for p in list(path.parents)[::-1] + [path]:
            mode = p.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise OSError('路径含符号链接，本批不跟随：' + str(p))
        if directory:
            if not path.is_dir():
                raise OSError('不是目录：' + str(path))
        elif not path.is_file():
            raise OSError('不是普通文件：' + str(path))

    try:
        log('范围及边界', 'G04-001～011；仅读监听、IPv6、防火墙管理状态及规则；不连接任何远程资产；不执行sshd/-T/-t/ssh连接，不读取密钥、密码哈希及密码历史。', 0)
        identity, rc = run(['uname', '-s', '-n', '-r', '-m'])
        if rc or identity != 'Linux lab-ubuntu20 5.4.0-216-generic x86_64':
            raise OSError('身份与已确认资产不一致，停止套用基线')
        distro, rc = run(['awk', '/^(ID|VERSION_ID)=/ {print}', '/etc/os-release'])
        if rc or not re.search(r'^ID="?ubuntu"?$', distro, re.M) or not re.search(r'^VERSION_ID="?20\.04"?$', distro, re.M):
            raise OSError('未确认Ubuntu 20.04')



        cache = {}

        def read(path, optional=False, compressed=False):
            path = Path(path)
            if str(path) in cache:
                return cache[str(path)]
            try:
                safe_file(path.parent, directory=True)
                try:
                    path.lstat()
                except FileNotFoundError:
                    if optional:
                        log('可选配置存在性：' + str(path), '文件不存在', 0)
                        cache[str(path)] = ''
                        return ''
                    raise
                safe_file(path)
                fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, 'rb') as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        raise OSError('不是普通文件')
                    if compressed:
                        with gzip.GzipFile(fileobj=stream) as zipped:
                            data = zipped.read(2 * 1024 * 1024 + 1)
                    else:
                        data = stream.read(2 * 1024 * 1024 + 1)
                if len(data) > 2 * 1024 * 1024:
                    raise OSError('超过2MiB读取上限')
                text = data.decode('utf-8')
                cache[str(path)] = text
                log('读取配置：' + str(path), '成功；只另行输出本批白名单字段', 0)
                return text
            except (OSError, UnicodeError, EOFError) as exc:
                log('读取失败：' + str(path), str(exc), 1)
                raise OSError(str(path) + '读取失败；见证据') from exc


        if os.geteuid()!=0: raise OSError('请使用目标Ubuntu已有root终端；不自动提权')
        assessed={}
        ss,ss_rc=run(['ss','-H','-lntup'])
        listening=None
        try:
            if ss_rc: raise ValueError('ss查询失败')
            listening=listeners(ss)
            external=[p+' '+endpoint for p,endpoint,loop in listening if not loop]
            assessed[1]=('待人工确认','共{}条监听；非回环：'.format(len(listening))+(short(external) or '未发现'),
                         '需确认服务/端口/绑定地址是否获准；监听不等于外部可达，进程名见证据')
        except ValueError as exc:
            assessed[1]=('待核实',str(exc),'未保存完整进程命令行')

        values,ipv6_errors,module={},[],None
        try:
            module=Path('/sys/module/ipv6/parameters/disable').read_text(encoding='ascii').strip()
            log('IPv6模块参数','disable='+module,0)
        except OSError as exc:
            ipv6_errors.append(str(exc)); log('IPv6模块参数读取失败',str(exc),1)
        try:
            folder=Path('/proc/sys/net/ipv6/conf')
            interfaces=list(folder.iterdir())
            if len(interfaces)>200: raise OSError('IPv6接口超过200个，未完整读取')
            for interface in interfaces:
                try:
                    value=(interface/'disable_ipv6').read_text(encoding='ascii').strip()
                    values[interface.name]=value
                    log('IPv6接口参数',interface.name+'.disable_ipv6='+value,0)
                except OSError as exc:
                    ipv6_errors.append(str(exc)); log('IPv6接口参数失败',str(exc),1)
            if not {'all','default'}.issubset(values): ipv6_errors.append('缺少all/default参数')
        except OSError as exc:
            ipv6_errors.append(str(exc)); log('IPv6接口枚举失败',str(exc),1)
        assessed[2],ipv6=ipv6_result(module,values,ipv6_errors)

        packages={}
        for package in ('ufw','nftables','iptables','iptables-persistent','firewalld'):
            output,rc=run(['dpkg-query','-W','-f=${Status}\t${Version}\n',package])
            if rc==0 and '\t' in output:
                state,version=output.split('\t',1)
                packages[package]=(state=='install ok installed',version,state)
            elif rc==1 and 'no packages found matching '+package in output:
                packages[package]=(False,'','dpkg无安装记录')
            else: packages[package]=(None,'','查询失败')
        units={}
        for service in ('ufw','nftables','iptables','ip6tables','netfilter-persistent','firewalld','docker'):
            output,rc=run(['systemctl','--system','--no-pager','show',
                           '--property=LoadState,ActiveState,SubState,UnitFileState','--',service+'.service'])
            units[service]=unit_parse(output,rc)
        ufw,ufw_rc=run(['ufw','status','verbose'],lambda s:'\n'.join(line.split('#',1)[0].rstrip() for line in s.splitlines()))
        state=ufw_state(ufw,ufw_rc)
        managers=[name for name in ('ufw','nftables','iptables','ip6tables','netfilter-persistent','firewalld') if active(units[name])]
        # iptables/ip6tables及netfilter-persistent属于同一管理方案；不把IPv4/IPv6算两套。
        families=set('iptables' if n in ('iptables','ip6tables','netfilter-persistent') else n for n in managers)
        gaps=[n for n,u in units.items() if n!='docker' and u is None]
        if len(families)>1:
            assessed[3]=('不符合','运行中的管理服务：'+','.join(managers),'多管理方案同时运行；安装iptables作为UFW后端本身不算冲突')
        elif gaps:
            assessed[3]=('待核实','管理服务状态不完整：'+','.join(gaps),'不能把查询失败当作未运行')
        elif families=={'ufw'} and enabled(units['ufw']) and state=='active':
            assessed[3]=('符合（管理服务检查）','已确认UFW启用并运行，未见其他所查管理服务运行','按基线服务口径；不证明全部自定义加载入口或容器规则不存在')
        elif len(families)==1:
            assessed[3]=('待核实','运行中的管理方案：'+','.join(families),'核对启用状态/规则来源后选择对应分支')
        else:
            assessed[3]=('待核实' if state=='active' else '不符合',
                         '未发现运行中的所查管理服务','可能存在直接加载的规则；运行规则见证据，不等同于断言无防护')
        applicable=state=='active' or (active(units['ufw']) and enabled(units['ufw']))
        installed,version,_=packages['ufw']
        assessed[4]=('待核实','ufw包查询失败','不能判断安装状态') if installed is None else (
                     '符合' if installed else '不符合','ufw='+version if installed else 'dpkg未安装ufw','')
        nft_installed=packages['nftables'][0]; nu=units['nftables']
        if nft_installed is False:
            assessed[5]=('符合','dpkg未安装nftables','不将iptables-nft后端误判为独立nftables服务')
        elif nu is None or nft_installed is None:
            assessed[5]=('待核实','nftables安装/服务状态查询不完整','错误见证据')
        else:
            inactive=nu['ActiveState']=='inactive'
            not_enabled=nu['LoadState']=='not-found' or nu['UnitFileState'] in ('disabled','masked','masked-runtime','static')
            assessed[5]=('符合' if inactive and not_enabled else '不符合',
                         'nftables：启用状态={}；运行状态={}'.format(nu['UnitFileState'] or nu['LoadState'],nu['ActiveState']),'')
        installed=packages['iptables-persistent'][0]
        assessed[6]=('待核实' if installed is None else '不符合' if installed else '符合',
                     'iptables-persistent='+('查询失败' if installed is None else '已安装' if installed else '未安装'),'')
        uu=units['ufw']
        assessed[7]=('待核实','未完整取得服务和ufw状态','错误见证据') if uu is None or state is None else (
            '符合' if uu['UnitFileState']=='enabled' and active(uu) and state=='active' else '不符合',
            '服务{} / {}；ufw {}'.format(uu['UnitFileState'] or uu['LoadState'],uu['ActiveState'],state),'')

        # 只导出现有表，不指定-t去请求未加载表；-M禁止调用实际modprobe。
        runtime={}; runtime_rc={}
        for family,command in ((4,'iptables-save'),(6,'ip6tables-save')):
            if family==6 and ipv6 is False: continue
            runtime[family],runtime_rc[family]=run([command,'-M','/bin/false'],clean_rules)
        docker_rules=[line for data in runtime.values() for line in data.splitlines()
                      if line.startswith('-A DOCKER') and '-j DNAT' in line]
        log('Docker发布端口线索（当前后端）','\n'.join(docker_rules) or '未发现DOCKER链DNAT条目；不能据此断言无容器发布端口',0)
        if docker_rules or active(units['docker']):
            v,a,w=assessed[1]
            assessed[1]=(v,a+'；Docker DNAT线索{}条'.format(len(docker_rules)),w+'；容器转发流量需结合DNAT/FORWARD链，不能只看UFW入站')
        configs={}
        for family,path in ((4,'/etc/ufw/before.rules'),(6,'/etc/ufw/before6.rules')):
            if family==6 and ipv6 is False: continue
            try:
                configs[family]=read(path)
                log('UFW回环配置：'+path,clean_rules(configs[family]),0)
            except OSError: configs[family]=None
        rule_ok=runtime_rc.get(4)==0 and (ipv6 is False or runtime_rc.get(6)==0)
        assessed[8]=loopback_result(configs,ufw,state,ipv6,rule_ok)
        rule_rows=[line.strip() for line in ufw.splitlines() if re.search(r'\b(?:ALLOW|DENY|REJECT|LIMIT)\s+(?:IN|OUT|FWD)\b',line)]
        outbound=[line for line in rule_rows if re.search(r'\bOUT\b',line)]
        assessed[9]=('待人工确认','显式出站规则：'+(short(outbound) or '未见'), '结合默认出站策略及业务依赖确认，未擅自批准放行') if state=='active' else (
                     '不符合' if state=='inactive' else '待核实','UFW未确认active','不能确认生效出站规则')
        external=[] if listening is None else [p+' '+ep for p,ep,lo in listening if not lo]
        assessed[10]=('待核实','非回环监听：'+(short(external) if listening is not None else '查询失败'),
                      '规则已采集；需逐项核对协议/地址/来源/链顺序，不按端口数字出现即判符合')
        if state=='inactive': assessed[10]=('不符合','UFW为inactive','未形成UFW端口规则保护')
        if not rule_ok: assessed[10]=('待核实',assessed[10][1],'运行规则未完整取得；不能判断覆盖情况')
        assessed[11]=default_result(ufw,ufw_rc)
        if not applicable:
            for i in range(4,12):
                v,a,w=assessed[i]
                assessed[i]=('待确认适用',a,'本轮未确认采用UFW方案；不把其他防火墙方案判成UFW不合规')

        lines=['G04-001～011｜监听、IPv6与UFW检查',
               '时间：'+datetime.now().astimezone().isoformat(timespec='seconds'),
               '依据：CIS Ubuntu Linux 20.04 LTS v3.0.0 / Level 1 Server',
               '本批仅读；端口批准清单和业务需求需人工确认；无连接测试。']
        for i,name,cis,pages,rule in ITEMS:
            verdict,actual,note=assessed[i]
            lines += ['', '[G04-{:03d}] {} | {}'.format(i,verdict,name),
                      '  基线：CIS {} / p.{}；推荐：{}'.format(cis,pages,rule),'  实际：'+actual]
            if note: lines.append('  说明：'+note)
        lines += ['', '详细证据：'+str(Path(proof_name).absolute()),
                  '只读当前网络命名空间和默认iptables后端；未覆盖其他网络命名空间/独立后端/容器专项。']
        fd,summary=tempfile.mkstemp(prefix='G04_001_011_结果_'+stamp+'_',suffix='.txt',dir='.')
        with os.fdopen(fd,'w',encoding='utf-8') as f: f.write('\n'.join(lines)+'\n')
        print('\n'.join(lines)); print('\n简明结果：'+str(Path(summary).absolute()))
    except (OSError,UnicodeError,KeyboardInterrupt) as exc:
        log('停止；本批不完整',str(exc),1)
        print('已停止：{}\n保留证据：{}'.format(exc,Path(proof_name).absolute()),file=sys.stderr)
        return 2
    finally:
        proof.close()
    return 0

if __name__=='__main__': sys.exit(main())

G04_PY
