#!/usr/bin/env bash
# 参数传入内嵌Python；只读检查，不自动提权。
if [[ ! -x /usr/bin/python3 ]]; then
  printf '%s\n' '缺少/usr/bin/python3，未执行检查；不自动安装。' >&2
  exit 127
fi
/usr/bin/python3 -I - "$@" <<'CIS_READONLY_PY'
BATCH = 'G05_010_016'
ITEMS = [{'number': 10, 'name': 'journal远程日志软件包', 'cis': '6.2.2.1.1', 'page': 709, 'rule': 'journald方案安装systemd-journal-remote'}, {'number': 11, 'name': 'journal上传认证配置', 'cis': '6.2.2.1.2', 'page': 711, 'rule': '授权URL及证书路径配置正确，不读取私钥'}, {'number': 12, 'name': 'journal上传服务状态', 'cis': '6.2.2.1.3', 'page': 713, 'rule': 'enabled且active'}, {'number': 13, 'name': '禁止journal接收远程日志', 'cis': '6.2.2.1.4', 'page': 715, 'rule': '客户端接收service/socket均未启用未运行'}, {'number': 14, 'name': 'journald不转交syslog', 'cis': '6.2.2.2', 'page': 717, 'rule': '独立journald方案ForwardToSyslog=no'}, {'number': 15, 'name': 'journald日志压缩', 'cis': '6.2.2.3', 'page': 719, 'rule': 'Compress=yes'}, {'number': 16, 'name': 'journald日志持久化', 'cis': '6.2.2.4', 'page': 721, 'rule': 'Storage=persistent'}]
import argparse
import collections
from datetime import datetime
import fnmatch
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

# BATCH and ITEMS are embedded by the builder. No import triggers collection.
def compact(xs, n=5):
    return '；'.join(str(x) for x in xs[:n])+('；另{}条见证据'.format(len(xs)-n) if len(xs)>n else '')

def scrub(text):
    # Keep only scheme/host/port for URLs; never retain userinfo, query or token paths.
    def repl(match):
        try:
            u=urlsplit(match[0]); host=u.hostname or '[主机未识别]'
            if ':' in host: host='['+host+']'
            return u.scheme+'://'+host+(':'+str(u.port) if u.port else '')+'/[路径及认证信息省略]'
        except ValueError: return '[URL已省略]'
    text=re.sub(r'\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"<>]+',repl,str(text))
    return re.sub(r'(?i)\b(password|passwd|token|secret|community)(\s*[=:]\s*)\S+',r'\1\2[省略]',text)

def package_state(output, rc):
    if rc==1 and 'no packages found matching ' in output: return False, '无包记录'
    if rc: return None, '查询失败(rc={})'.format(rc)
    lines=output.splitlines()
    if not lines: return None, '空输出'
    status=lines[0].strip()
    if status=='install ok installed': return True, lines[1].strip() if len(lines)>1 else '版本未返回'
    if status.endswith(' not-installed') or status.endswith(' config-files'):
        return False, status
    return None, '未完整安装或状态异常：'+status

def unit_state(output, rc):
    if rc: return None
    d=dict(x.split('=',1) for x in output.splitlines() if '=' in x)
    if not {'LoadState','ActiveState','UnitFileState'}.issubset(d): return None
    if d['LoadState'] not in ('loaded','not-found','masked'): return None
    return d

def unit_off(u):
    if u is None: return None
    if u['ActiveState']=='active' or u['UnitFileState'] in ('enabled','enabled-runtime'): return False
    if u['LoadState']=='not-found': return True
    if u['ActiveState'] in ('inactive','failed') and u['UnitFileState'] in ('disabled','masked','masked-runtime','static','indirect',''):
        return True
    return None

def unit_on(u, static=False):
    if u is None: return None
    return u['ActiveState']=='active' and u['UnitFileState']==('static' if static else 'enabled')

def unit_label(u):
    return '查询失败' if u is None else '/'.join(u.get(k,'') or '-' for k in ('LoadState','UnitFileState','ActiveState'))

def tri(value,actual,why=''):
    return ('待核实' if value is None else '符合' if value else '不符合',actual,why)

def listen_rows(text):
    rows=[]
    for line in text.splitlines():
        f=line.split()
        if len(f)<6 or f[0] not in ('tcp','udp'): raise ValueError('监听输出格式异常')
        addr,port=f[4].rsplit(':',1)
        if not port.isdigit(): raise ValueError('端口不是数字')
        host=addr.strip('[]').split('%',1)[0]
        loop=host!='*' and ipaddress.ip_address(host).is_loopback
        rows.append((f[0],host,int(port),loop))
    return rows

def safe_rules(text):
    keep={'-A','-p','-s','-d','-i','-o','-j','-g','--sport','--dport','--sports','--dports',
          '--to-destination','--ctstate','--state','--reject-with','-m'}
    out=[]
    for line in text.splitlines():
        if line.startswith(('*',':')): out.append(line); continue
        if not line.startswith('-A '): continue
        p=shlex.split(line); row=[]; i=0
        while i<len(p):
            if p[i]=='--comment' or (p[i]=='-m' and i+1<len(p) and p[i+1] in ('comment','string')):
                i+=2
            elif p[i] in keep and i+1<len(p): row+=p[i:i+2]; i+=2
            elif p[i]=='!': row.append('!'); i+=1
            else:
                row.append('[其他条件省略]'); i+=1
                if i<len(p) and not p[i].startswith('-'): i+=1
        out.append(shlex.join(row))
    return '\n'.join(out)

class Audit:
    def __init__(self,args):
        self.args=args; self.cache={}; self.pkgs={}; self.units={}; self.results={}
        self.stamp=datetime.now().strftime('%Y%m%d_%H%M%S'); self.q=0
        fd,self.proof_path=tempfile.mkstemp(prefix=BATCH+'_证据_'+self.stamp+'_',suffix='.txt',dir='.')
        self.proof=os.fdopen(fd,'w',encoding='utf-8',buffering=1); self.mounts=None
    def log(self,title,output,rc=0):
        self.q+=1
        self.proof.write('[E-{}] {}\n输出与错误（安全字段）：\n{}\n退出码/读取状态码：{}\n\n'.format(self.q,title,scrub(output),rc))
    def run(self,args,transform=None):
        key=tuple(args)
        if key in self.cache: return self.cache[key]
        try:
            p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=12,
                             text=True,encoding='utf-8',errors='replace')
            output=p.stdout; error=p.stderr; rc=p.returncode
            if len(output)>4*1024*1024:
                output='输出超过4MiB，未按完整结果判断'; rc=75
            elif transform is not None:
                output=transform(output)
            self.log('命令：'+shlex.join(args),output+('\n错误：'+error if error else ''),rc)
        except subprocess.TimeoutExpired:
            output,error,rc='查询超过12秒，未保留不完整输出','',124
            self.log('命令：'+shlex.join(args),output,rc)
        except (OSError,ValueError,TypeError) as exc:
            output,error,rc=str(exc),'',127 if isinstance(exc,FileNotFoundError) else 1
            self.log('命令：'+shlex.join(args),output,rc)
        # Return errors too for status commands; never discard absence/error distinctions.
        self.cache[key]=(output.strip()+('\n'+error.strip() if rc and error.strip() else ''),rc)
        return self.cache[key]
    def package(self,name):
        if name not in self.pkgs:
            self.pkgs[name]=package_state(*self.run(['dpkg-query','-W','-f=${Status}\n${Version}\n',name]))
        return self.pkgs[name]
    def unit(self,name):
        if name not in self.units:
            self.units[name]=unit_state(*self.run(['systemctl','--system','--no-pager','show',
              '--property=LoadState,UnitFileState,ActiveState,SubState,MainPID','--',name]))
        return self.units[name]
    def local(self,path):
        if self.mounts is None:
            text,rc=self.run(['findmnt','-rn','--raw','-o','TARGET,FSTYPE'])
            if rc: raise OSError('未取得本地挂载表')
            self.mounts=[]
            for line in text.splitlines():
                f=line.split()
                if len(f)!=2: raise OSError('挂载表格式异常')
                target=re.sub(r'\\x([0-9a-fA-F]{2})',lambda m:chr(int(m[1],16)),f[0])
                self.mounts.append((target,f[1]))
            self.mounts.sort(key=lambda x:len(x[0]),reverse=True)
        if not str(path).startswith('/') or '..' in Path(path).parts: raise OSError('非安全绝对路径')
        for prefix in list(Path(path).parents)[::-1]+[Path(path)]:
            s=str(prefix)
            fs=next((f for m,f in self.mounts if s==m or s.startswith(m.rstrip('/')+'/')),None)
            if fs not in ('ext2','ext3','ext4','xfs','btrfs','tmpfs','overlay','zfs'):
                raise OSError('跳过非本地或未支持文件系统：'+s)
            if stat.S_ISLNK(prefix.lstat().st_mode):
                # Standard usrmerge aliases are validated explicitly; config symlinks remain gaps.
                target=os.readlink(prefix)
                if s in ('/lib','/bin','/sbin') and target in ('usr'+s,'/usr'+s):
                    self.local('/usr'+s)
                else: raise OSError('符号链接未跟随：'+s)
    def read(self,path,optional=False):
        key=('file',str(path))
        if key in self.cache: return self.cache[key]
        try:
            self.local(Path(path).parent)
            try: self.local(path)
            except FileNotFoundError:
                if optional:
                    self.log('文件存在性',str(path)+'不存在',0); self.cache[key]=''; return ''
                raise
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as f:
                if not stat.S_ISREG(os.fstat(f.fileno()).st_mode): raise OSError('不是普通配置文件')
                raw=f.read(512*1024+1)
            if len(raw)>512*1024: raise OSError('配置超过512KiB')
            value=raw.decode('utf-8'); self.cache[key]=value
            self.log('读取配置',str(path)+'：成功，仅另行记录白名单字段',0); return value
        except (OSError,UnicodeError) as exc:
            self.log('配置读取失败',str(path)+'：'+str(exc),1); raise OSError(str(path)+'读取不完整')
    def config_set(self,base,directory):
        files=[base]; gaps=[]
        if directory:
            try:
                self.local(Path(directory).parent)
                self.local(directory); names=list(Path(directory).iterdir())
                if len(names)>200: raise OSError('配置目录超过200项')
                files += sorted(str(p) for p in names if p.name.endswith('.conf'))
            except FileNotFoundError: pass
            except OSError as exc: gaps.append(str(exc))
        data={}
        for f in files:
            try: data[f]=self.read(f,optional=True)
            except OSError as exc: gaps.append(str(exc))
        return data,gaps
    def systemd_config(self,name,keys,section):
        # cat-config does not execute unit/config files; parse only named section/keys.
        def selected(text):
            out=[]; current=''; source='未标明来源'
            for line in text.splitlines():
                if line.startswith('# /'): source=line[2:]; continue
                clean=line.strip()
                if clean.startswith('['): current=clean; continue
                if current!='['+section+']' or clean.startswith(('#',';')): continue
                m=re.match(r'^([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*?)\s*$',clean)
                if m and m[1] in keys: out.append(json.dumps([source,m[1],scrub(m[2])],ensure_ascii=False))
            return '\n'.join(out)
        # Validate config locations before cat-config to avoid following unchecked remote/symlink files.
        for prefix in ('/usr/lib/systemd','/usr/local/lib/systemd','/lib/systemd','/run/systemd','/etc/systemd'):
            for p in (prefix+'/'+name, prefix+'/'+name+'.d'):
                try:
                    self.local(Path(p).parent)
                    self.local(p)
                    if Path(p).is_dir():
                        names=list(Path(p).iterdir())
                        if len(names)>200: raise OSError('配置目录过大')
                        for f in names:
                            if f.name.endswith('.conf'): self.local(f)
                except FileNotFoundError: pass
                except OSError as exc:
                    self.log('配置覆盖范围限制',str(exc),1)
                    return {},[str(exc)]
        text,rc=self.run(['systemd-analyze','cat-config','systemd/'+name],selected)
        values={}
        if rc: return {},['无法完整读取合并配置（工具可能不支持cat-config）']
        try:
            for line in text.splitlines():
                source,key,val=json.loads(line); values.setdefault(key,[]).append((source,val))
        except ValueError: return {},['合并配置解析失败']
        return values,[]
    def set(self,i,v):
        self.results[i]=v
        self.log('{}-{:03d} 判断'.format(BATCH[:3],i),' | '.join(v))
    def manual(self,i,actual,why='需本地策略或人工核对证据'):
        self.set(i,('待核实',actual,why))
    def finish(self):
        lines=[BATCH+'｜只读检查结果','时间：'+datetime.now().astimezone().isoformat(timespec='seconds'),
               '依据：CIS Ubuntu Linux 20.04 LTS v3.0.0 / Level 1 Server',
               '范围：本批列出的条目；不安装、不改配置、不执行服务操作、不连接其他资产。']
        for item in ITEMS:
            i=item['number']; verdict,actual,why=self.results.get(i,('待核实','本项未完成','存在全局取证限制，见证据'))
            lines+=['','[{}-{:03d}] {} | {}'.format(BATCH[:3],i,verdict,item['name']),
                    '  基线：CIS {} / p.{}；推荐：{}'.format(item['cis'],item['page'],item['rule']),
                    '  实际：'+scrub(actual)]
            if why: lines.append('  说明：'+scrub(why))
        lines+=['','详细证据：'+str(Path(self.proof_path).absolute())]
        fd,path=tempfile.mkstemp(prefix=BATCH+'_结果_'+self.stamp+'_',suffix='.txt',dir='.')
        with os.fdopen(fd,'w',encoding='utf-8') as f: f.write('\n'.join(lines)+'\n')
        print('\n'.join(lines)); print('\n简明结果：'+str(Path(path).absolute())); self.proof.close()

def main():
    parser=argparse.ArgumentParser(description='只读基线批次；参数只指定已确认的检查方案，不修改系统')
    parser.add_argument('--firewall',choices=['auto','ufw','nftables','iptables'],default='auto')
    parser.add_argument('--logging',choices=['auto','journald','rsyslog'],default='auto')
    args=parser.parse_args()
    if sys.platform!='linux': raise SystemExit('仅在目标Ubuntu运行；没有执行采集')
    os.environ['PATH']='/usr/sbin:/usr/bin:/sbin:/bin'; os.environ['LC_ALL']='C'; os.umask(0o077)
    a=Audit(args); rc=0
    try:
        if os.geteuid()!=0: raise OSError('需要现有root终端；不自动提权')
        identity,code=a.run(['uname','-s','-n','-r','-m'])
        if code or identity!='Linux lab-ubuntu20 5.4.0-216-generic x86_64': raise OSError('资产身份/内核与已确认环境不一致，停止')
        distro,code=a.run(['awk','/^(ID|VERSION_ID)=/ {print}','/etc/os-release'])
        if code or not re.search(r'^ID="?ubuntu"?$',distro,re.M) or not re.search(r'^VERSION_ID="?20\.04"?$',distro,re.M):
            raise OSError('未确认Ubuntu 20.04')
        if BATCH[:3]=='G04': firewall_checks(a)
        elif BATCH[:3]=='G05': logging_checks(a)
        elif BATCH[:3]=='G06': software_checks(a)
        else: raise ValueError('未知检查组')
    except (OSError,ValueError,KeyError,UnicodeError,KeyboardInterrupt) as exc:
        a.log('本批存在未完成检查',str(exc),1); rc=2
    finally: a.finish()
    return rc

def configured_value(a,i,values,gaps,key,want):
    entries=values.get(key,[])
    actual=key+'='+entries[-1][1] if entries else '所查合并配置未声明'+key
    if gaps: a.manual(i,actual,'配置读取不完整；'+compact(gaps)); return
    if not entries: a.set(i,('不符合',actual,'本条要求显式配置；未以默认值替代')); return
    a.set(i,tri(entries[-1][1].lower()==want.lower(),actual,'按配置覆盖结果判断，未重载服务'))

def logging_branch(a):
    rs=a.unit('rsyslog.service'); jo=a.unit('systemd-journald.service')
    if a.args.logging!='auto':
        a.log('日志方案','按用户参数选择：'+a.args.logging+'；参数不会改变系统')
        return a.args.logging
    if unit_on(rs):
        a.log('日志方案线索','rsyslog已启用运行；推定rsyslog为候选方案，独立journald分支仍待确认适用')
        return 'candidate-rsyslog'
    a.log('日志方案线索','服务状态不能独立证明组织选择了独立journald方案；继续按条件取证')
    return 'unknown'

def service_result(a,i,name,static=False):
    u=a.unit(name); a.set(i,tri(unit_on(u,static),name+' '+unit_label(u)))

def metadata_logs(a):
    usertext,urc=a.run(['awk','-F:','$1=="root" || $1=="syslog" || $1=="SSSD" {print $1 ":" $3}','/etc/passwd'])
    grouptext,grc=a.run(['awk','-F:','$1=="root" || $1=="adm" || $1=="utmp" || $1=="systemd-journal" || $1=="SSSD" || $1=="gdm" || $1=="gdm3" {print $1 ":" $3}','/etc/group'])
    if urc or grc: raise OSError('日志属主/属组本地编号未完整取得')
    users={k:int(v) for k,v in (line.split(':') for line in usertext.splitlines())}
    groups={k:int(v) for k,v in (line.split(':') for line in grouptext.splitlines())}
    a.local('/var/log'); stack=[Path('/var/log')]; count=0; bad=[]; pending=[]; start=time.monotonic()
    while stack:
        folder=stack.pop()
        if count>20000 or time.monotonic()-start>25:
            pending.append('达到20000项/25秒上限，剩余范围未查'); break
        try:
            a.local(folder)
            with os.scandir(folder) as it:
                for ent in it:
                    count+=1
                    if count>20000 or time.monotonic()-start>25:
                        pending.append('达到遍历上限，剩余范围未查'); stack=[]; break
                    p=Path(ent.path)
                    try:
                        a.local(p); st=ent.stat(follow_symlinks=False)
                        if stat.S_ISDIR(st.st_mode): stack.append(p); continue
                        if not stat.S_ISREG(st.st_mode): continue
                        name=p.name; mode=stat.S_IMODE(st.st_mode)
                        allowed_users={'root','syslog'}; allowed_groups={'root','adm'}; mask=0o137; flexible=False
                        if p.parent.name=='apt': mask=0o133; allowed_users={'root'}
                        elif re.match(r'^(lastlog(?:\.|$)|[wb]tmp(?:[.-]|$)|README$)',name):
                            mask=0o113; allowed_users={'root'}; allowed_groups={'root','utmp'}
                        elif name.startswith(('cloud-init.log','localmessages','waagent.log')): mask=0o133
                        elif name.endswith(('.journal','.journal~')):
                            allowed_users={'root'}; allowed_groups={'root','systemd-journal'}
                        elif name in ('SSSD','sssd'):
                            mask=0o117; allowed_users={'root','SSSD'}; allowed_groups={'root','SSSD'}
                        elif name in ('gdm','gdm3'):
                            mask=0o117; allowed_users={'root'}; allowed_groups={'root','gdm','gdm3'}
                        elif name not in ('auth.log','syslog','messages','secure'): flexible=True
                        detail='{} UID={} GID={} 权限={:04o}'.format(p,st.st_uid,st.st_gid,mode)
                        a.log('日志文件元数据',detail)
                        owner_ok=st.st_uid in {users[n] for n in allowed_users if n in users}
                        group_ok=st.st_gid in {groups[n] for n in allowed_groups if n in groups}
                        if mode & mask: bad.append(detail)
                        elif not(owner_ok and group_ok):
                            (pending if flexible else bad).append(detail+('；需核对服务账号例外' if flexible else '；属主/属组不符'))
                    except OSError as exc: pending.append(str(p)+'：'+str(exc))
        except OSError as exc: pending.append(str(folder)+'：'+str(exc))
    a.log('日志权限全部异常','\n'.join(bad+pending) or '未发现',1 if pending else 0)
    if bad: return '不符合',compact(bad),'另有待核实范围' if pending else '按原文日志类型分类；不读取日志正文'
    return '待核实','已遍历{}项；'.format(count)+(compact(pending) if pending else '/var/log所查文件未发现权限异常'),'其他日志位置及服务账号例外需确认；仅读元数据'

def logging_checks(a):
    nums={x['number'] for x in ITEMS}
    if 1 in nums:
        ts=a.unit('systemd-timesyncd.service'); ch=a.unit('chrony.service')
        used=[n for n,u in [('timesyncd',ts),('chrony',ch)] if unit_off(u) is False]
        time_known=ts is not None and ch is not None
        a.log('时间同步范围','仅查询本机服务；不连接时间服务器，不运行校时。宿主同步方式需人工确认。')
        if len(used)>1: a.set(1,('不符合','timesyncd和chrony均启用或运行','存在多种守护进程；不执行停用'))
        else: a.manual(1,'时间守护进程：'+(','.join(used) or '未确认'),
                       '目标为虚拟机；还需确认宿主同步，不能仅凭客户机服务断言只有一种同步方式')
        if used==['chrony'] and time_known:
            for i in (2,3): a.set(i,('不适用（按当前守护进程）','已识别chrony方案','若宿主同步另有配置，需要重新确认'))
        else:
            vals,gaps=a.systemd_config('timesyncd.conf',{'NTP','FallbackNTP'},'Time')
            actual=[k+'='+v[-1][1] for k,v in vals.items() if v]
            a.manual(2,compact(actual) or '未见显式NTP/FallbackNTP',
                     '时间源是否获准需人工确认；还需考虑逐接口/动态时间源'+('；配置读取有缺口' if gaps else ''))
            service_result(a,3,'systemd-timesyncd.service')
        if used==['timesyncd'] and time_known:
            for i in (4,5,6): a.set(i,('不适用（按当前守护进程）','已识别timesyncd方案','未要求额外安装chrony'))
        else:
            try:
                text=a.read('/etc/chrony/chrony.conf',optional=True)
                fields=[]
                for line in text.splitlines():
                    line=line.split('#',1)[0].strip()
                    if re.match(r'^(server|pool|confdir|sourcedir|include)\s+',line):
                        f=line.split(); fields.append(' '.join(f[:2]))
                a.log('chrony时间源/引用', '\n'.join(fields) or '未见声明')
                a.manual(4,compact(fields) or '未见主配置时间源','需核对授权时间源及引入文件；未连接NTP服务器')
            except OSError as exc: a.manual(4,str(exc))
            output,rc=a.run(['ps','-C','chronyd','-o','uid=,pid=,comm='])
            uidtext,uidrc=a.run(['awk','-F:','$1=="_chrony" {print $3}','/etc/passwd'])
            if rc or uidrc or not uidtext.isdigit() or not output:
                a.manual(5,'chronyd进程或_chrony账号未完整取得','不把无进程当作运行用户符合')
            else:
                rows=[line.split() for line in output.splitlines()]
                a.set(5,tri(all(len(r)==3 and r[0]==uidtext for r in rows),compact([' '.join(r) for r in rows]),'只查UID/PID/进程名，不查命令行'))
            service_result(a,6,'chrony.service')
        if len(used)!=1 or not time_known:
            for i in range(2,7):
                v,x,w=a.results[i]
                a.set(i,('待确认适用',x,'尚未确认单一时间同步方案；条件判断为'+v+'；'+w))
        service_result(a,7,'systemd-journald.service',True)
        fields=[]; gaps=[]
        for path in ('/usr/lib/tmpfiles.d/systemd.conf','/run/tmpfiles.d/systemd.conf','/etc/tmpfiles.d/systemd.conf'):
            try:
                text=a.read(path,optional=True)
                for line in text.splitlines():
                    f=line.split()
                    if len(f)>=5 and f[0] in ('f','d','z','Z') and ('journal' in f[1] or f[1] in ('/run','/var/lib/systemd')):
                        fields.append(path+' '+' '.join(f[:5]))
            except OSError as exc: gaps.append(str(exc))
        a.log('journald创建权限白名单','\n'.join(fields) or '未取得相关声明')
        a.manual(8,compact(fields) or '未取得完整创建权限配置','需核对tmpfiles同名覆盖、类型要求及实际元数据'+('；有读取缺口' if gaps else ''))
        keys={'SystemMaxUse','SystemKeepFree','RuntimeMaxUse','RuntimeKeepFree','MaxFileSec'}
        vals,gaps=a.systemd_config('journald.conf',keys,'Journal')
        a.manual(9,compact([k+'='+vals[k][-1][1] if k in vals else k+'未显式配置' for k in sorted(keys)]),
                 '容量和轮转时限需符合本地策略'+('；配置读取有缺口' if gaps else ''))
    if 10 in nums:
        branch=logging_branch(a)
        if branch in ('rsyslog','candidate-rsyslog'):
            for i in range(10,17): a.set(i,('不适用' if branch=='rsyslog' else '待确认适用',
              '已选择rsyslog方案' if branch=='rsyslog' else '检测到rsyslog运行，需确认日志方案',
              '本批为独立journald日志方案；未因包未安装判不符合'))
            return
        state,version=a.package('systemd-journal-remote'); a.set(10,tri(state,'systemd-journal-remote：'+version))
        vals,gaps=a.systemd_config('journal-upload.conf',{'URL','ServerKeyFile','ServerCertificateFile','TrustedCertificateFile'},'Upload')
        a.manual(11,compact([k+'='+v[-1][1] for k,v in vals.items()]) or '未见完整上传认证字段',
                 '核对授权目标及证书路径；不读取私钥、不触发上传'+('；配置读取有缺口' if gaps else ''))
        service_result(a,12,'systemd-journal-upload.service')
        states=[a.unit(n) for n in ('systemd-journal-remote.service','systemd-journal-remote.socket')]
        off=[unit_off(u) for u in states]
        a.set(13,tri(None if None in off else all(off),'接收service/socket：'+compact([unit_label(u) for u in states]),'按日志客户端角色要求；日志服务器角色需另行确认'))
        vals,gaps=a.systemd_config('journald.conf',{'ForwardToSyslog','Compress','Storage'},'Journal')
        for i,k,w in [(14,'ForwardToSyslog','no'),(15,'Compress','yes'),(16,'Storage','persistent')]: configured_value(a,i,vals,gaps,k,w)
        if branch=='unknown':
            for i in range(10,17):
                v,x,w=a.results[i]; a.set(i,('待确认适用',x,'独立journald方案尚未确认；条件判断为'+v+'；'+w))
    if 17 in nums:
        branch=logging_branch(a)
        if branch=='journald':
            for i in range(17,25): a.set(i,('不适用','已选择独立journald方案','本项为rsyslog方案'))
        else:
            service_result(a,17,'rsyslog.service'); state,version=a.package('rsyslog')
            a.set(18,tri(state,'rsyslog：'+version))
            vals,gaps=a.systemd_config('journald.conf',{'ForwardToSyslog'},'Journal')
            configured_value(a,19,vals,gaps,'ForwardToSyslog','yes')
            if not (unit_on(a.unit('rsyslog.service')) and unit_on(a.unit('systemd-journald.service'),True)):
                a.manual(19,a.results[19][1],'两项服务状态尚未同时满足；见证据')
            data,errors=a.config_set('/etc/rsyslog.conf','/etc/rsyslog.d')
            modes=[]; inputs=[]; forwards=[]; destinations=[]; includes=[]
            for path,text in data.items():
                for n,line in enumerate(text.splitlines(),1):
                    line=line.split('#',1)[0].strip()
                    origin='{}:{}'.format(path,n)
                    m=re.match(r'^\$FileCreateMode\s+([0-7]{3,4})\s*$',line)
                    if m: modes.append((origin,int(m[1],8)))
                    for m in re.finditer(r'\bfileCreateMode\s*=\s*"([0-7]{3,4})"',line,re.I): modes.append((origin,int(m[1],8)))
                    if re.search(r'(?:\b(?:imtcp|imudp)\b|^\$(?:InputTCPServerRun|UDPServerRun))',line): inputs.append(origin+' 网络输入声明')
                    if re.match(r'^\$IncludeConfig\b',line) or re.search(r'\binclude\s*\(',line):
                        includes.append(origin+' 包含引用（需核对实际引入范围）')
                    if re.search(r'\bomfwd\b|\s@@?\S',line):
                        target=re.search(r'\btarget\s*=\s*"([^"\n]+)"',line)
                        old=re.search(r'\s(@@?)([^\s;]+)',line)
                        forwards.append(origin+' '+('target='+scrub(target[1]) if target else scrub(old[0].strip()) if old else 'omfwd声明（目标可能跨行）'))
                    match=re.match(r'^([A-Za-z0-9*.,;!=_-]+)\s+-?(/[^\s;]+)',line)
                    if match: destinations.append(origin+' '+match[1]+' -> '+match[2])
            for label,rows in [('文件创建模式',['{}={:04o}'.format(p,m) for p,m in modes]),('网络输入',inputs),('远程转发',forwards),('日志落盘目标',destinations),('引用范围',includes)]:
                a.log('rsyslog '+label,'\n'.join(rows) or '未匹配所查声明',1 if errors else 0)
            a.manual(20,compact(['{}={:04o}'.format(p,m) for p,m in modes]) or '未见FileCreateMode声明',
                     '需核对引用顺序及各action覆盖；要求不宽于0640，未以字符串出现即判符合')
            a.manual(21,compact(destinations) or '未识别单行日志落盘规则','需核对所需事件及落盘证据；不读取日志正文或制造测试事件')
            a.manual(22,compact(forwards) or '未识别单行远程转发规则','需确认目标获准及多行action；不联网、不发送日志，不证明远端接收')
            if inputs: a.set(23,('不符合',compact(inputs),'按普通日志客户端要求；日志服务器需记录角色例外'))
            else: a.manual(23,'所查配置未匹配网络输入声明','需核对完整引入范围、多行写法及自定义端口；未把无匹配当成符合')
            data,err=a.config_set('/etc/logrotate.conf',None)
            rotation=[]
            try:
                a.local('/etc/logrotate.d'); files=list(Path('/etc/logrotate.d').iterdir())
                if len(files)>150: raise OSError('logrotate文件过多')
                for p in files:
                    a.local(p)
                    if stat.S_ISREG(p.lstat().st_mode): data[str(p)]=a.read(str(p))
            except OSError as exc: err.append(str(exc))
            for path,text in data.items():
                # Do not capture postrotate/prerotate script bodies or execute any scripts.
                script=False
                for n,line in enumerate(text.splitlines(),1):
                    line=line.split('#',1)[0].strip()
                    if line in ('postrotate','prerotate','firstaction','lastaction','preremove'): script=True; continue
                    if line=='endscript': script=False; continue
                    if not script and re.match(r'^(daily|weekly|monthly|yearly|hourly|rotate|size|maxsize|minsize|maxage|compress|nocompress|delaycompress|create|include)\b',line):
                        rotation.append('{}:{} {}'.format(path,n,line))
            a.log('logrotate安全配置字段','\n'.join(rotation) or '未取得轮转声明',1 if err else 0)
            a.manual(24,compact(rotation) or '未取得轮转配置','数值须符合本地策略；不执行logrotate或附带脚本')
            if branch=='unknown':
                for i in range(17,25):
                    v,x,w=a.results[i]; a.set(i,('待确认适用',x,'rsyslog方案未确认；条件判断为'+v+'；'+w))
        try:
            value=metadata_logs(a)
            if len(value)==2: value=value+('其他日志位置及服务账号例外需确认；仅读元数据',)
            a.set(25,value)
        except OSError as exc: a.manual(25,str(exc),'日志权限检查未完整执行')

if __name__ == "__main__": sys.exit(main())

CIS_READONLY_PY
