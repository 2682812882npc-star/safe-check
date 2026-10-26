#!/usr/bin/env bash
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  printf '%s\n' '请用bash执行，不要source。' >&2
  return 2
fi
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' '停止：缺少python3；不安装软件。' >&2
  exit 127
fi
python3 - <<'PY_G02_018_024'
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




BASE=Path('/etc/pam.d')
TARGETS={'pam_pwquality.so','pam_faillock.so'}
ALTERNATIVES={'pam_cracklib.so','pam_passwdqc.so','pam_tally.so','pam_tally2.so','pam_pwhistory.so'}
EXTERNAL={'pam_sss.so','pam_ldap.so','pam_winbind.so','pam_krb5.so'}
DYNAMIC={'pam_exec.so','pam_python.so','pam_script.so'}
NUMBER_KEYS={'deny','unlock_time','fail_interval','retry','minlen','difok','minclass','dcredit','ucredit','lcredit','ocredit','maxrepeat','maxsequence','dictcheck','enforcing','remember'}
FLAGS={'preauth','authfail','authsucc','enforce_for_root','even_deny_root','use_authtok','try_first_pass','nullok','nullok_secure','sha512','yescrypt','sha256','md5','bigcrypt','blowfish','des','gost_yescrypt'}

def service_name(value):
    if value.startswith('/etc/pam.d/'):
        value=value[len('/etc/pam.d/'):]
    if value not in ('.','..') and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',value):
        return value
    return None

def safe_options(args):
    result=[]
    for token in args.split():
        if token in FLAGS: result.append(token)
        else:
            k,sep,v=token.partition('=')
            if sep and k in NUMBER_KEYS and re.fullmatch(r'-?\d{1,9}',v): result.append(token)
    return result

def parse_config(text):
    records=[]; errors=[]; pending=''; first=0
    for n,raw in enumerate(text.splitlines(),1):
        stripped=raw.split('#',1)[0].strip()
        if not pending: first=n
        if stripped.endswith('\\'):
            pending+=stripped[:-1]+' '; continue
        line=(pending+stripped).strip(); pending=''
        if not line: continue
        m=re.fullmatch(r'@include\s+(\S+)',line)
        if m:
            target=service_name(m[1])
            if target: records.append(('include',None,'@include',target,[],first,False))
            else: errors.append('第{}行：引用不在允许的/etc/pam.d单层路径范围，未读取'.format(first))
            continue
        m=re.fullmatch(r'(-?(?:auth|account|password|session))\s+(\[[^\]]+\]|\S+)\s+(\S+)(?:\s+(.*))?',line)
        if not m:
            errors.append('第{}行：PAM语法未识别，未输出原文'.format(first)); continue
        kind,control,module,args=m[1].lstrip('-'),m[2],m[3],m[4] or ''
        if control in ('include','substack'):
            target=service_name(module)
            if target and not args: records.append(('include',kind,control,target,[],first,False))
            else: errors.append('第{}行：复杂引用未展开'.format(first))
        else:
            name=Path(module).name
            if not re.fullmatch(r'[A-Za-z0-9_.-]+',name):
                errors.append('第{}行：模块名称未识别'.format(first)); continue
            if name in ('pam_unix.so','pam_pwhistory.so'):
                if any(c in args for c in (chr(34),chr(39),chr(92))):
                    errors.append('第{}行：相关模块有复杂参数写法，未完整解析'.format(first))
                for token in args.split():
                    if token == 'remember' or (token.startswith('remember=') and not re.fullmatch(r'remember=-?\d{1,9}', token)):
                        errors.append('第{}行：remember参数写法未识别'.format(first))
                    if any(token.startswith(k+'=') for k in ('nullok','use_authtok','enforce_for_root')):
                        errors.append('第{}行：开关被写成赋值形式，未解释'.format(first))
            records.append(('module',kind,control,name,safe_options(args),first,'/' in module))
    if pending: errors.append('文件末尾存在未完成续行')
    return records,errors

def trace_service(entry,read_config):
    hits=[]; edges=[]; gaps=[]; seen=set()
    def walk(name,kind=None,active=()):
        state=(name,kind)
        if state in active:
            gaps.append(name+': 发现循环引用，停止此分支'); return
        if state in seen: return
        if len(active)>=16 or len(seen)>=128:
            gaps.append(name+': 引用深度/数量超过上限'); return
        seen.add(state)
        records,errors=read_config(name)
        gaps.extend(name+': '+e for e in errors)
        for typ,rkind,control,target,options,line,custom in records:
            if kind is not None and rkind is not None and rkind!=kind: continue
            if typ=='include':
                edges.append('{}:{} --{}({})--> {}'.format(name,line,control,rkind or kind or '全部类型',target))
                walk(target,rkind or kind,active+(state,))
            else:
                hits.append((name,line,rkind,control,target,options,custom))
    walk(entry)
    return hits,list(dict.fromkeys(edges)),list(dict.fromkeys(gaps)),seen


COMMON=['common-auth','common-account','common-password','common-session','common-session-noninteractive']
ITEMS=[
 (18,'密码历史次数','5.3.3.3.1','621–623','pam_pwhistory包含remember≥24'),
 (19,'root执行密码历史','5.3.3.3.2','624–626','pam_pwhistory包含enforce_for_root'),
 (20,'历史模块沿用新口令','5.3.3.3.3','627–629','pam_pwhistory包含use_authtok'),
 (21,'pam_unix空口令选项','5.3.3.4.1','630–632','pam_unix不包含nullok'),
 (22,'pam_unix旧式历史选项','5.3.3.4.2','633–634','pam_unix不包含remember参数'),
 (23,'pam_unix密码哈希算法','5.3.3.4.3','635–637','password类型配置sha512；yescrypt须确认支持'),
 (24,'pam_unix沿用新口令','5.3.3.4.4','638–642','password类型pam_unix包含use_authtok'),
]

def assess(index,hits,gaps):
    if index<=20: relevant=[h for h in hits if h[2]=='password' and h[4]=='pam_pwhistory.so']
    else: relevant=[h for h in hits if h[4]=='pam_unix.so' and (index in (21,22) or h[2]=='password')]
    if gaps or any(h[6] for h in relevant):
        return '待核实','存在读取/引用/解析缺口或自定义模块身份未确认'
    if not relevant:
        return ('不符合','所查password配置未见pam_pwhistory；历史策略未通过该模块落实') if index<=20 else ('待核实','未取得适用的pam_unix声明，不能据空输出判符合')
    if index<=20 and any(h[3] not in ('required','requisite') for h in relevant):
        return '待核实','pam_pwhistory存在，但控制字段需结合调用关系判断'
    if index==18:
        for h in relevant:
            vals=[int(t.split('=',1)[1]) for t in h[5] if t.startswith('remember=')]
            if len(vals)>1 and len(set(vals))>1: return '待核实','同一声明含冲突remember值'
            if not vals or vals[0]<24: return '不符合','pam_pwhistory缺少remember≥24的参数'
        return '符合','所查pam_pwhistory的remember均不小于24'
    if index in (19,20,24):
        key='enforce_for_root' if index==19 else 'use_authtok'
        good=all(key in h[5] for h in relevant)
        return ('符合' if good else '不符合'),('所查适用声明均包含' if good else '所查适用声明缺少')+key
    if index==21:
        if any('nullok' in h[5] for h in relevant): return '不符合','所查pam_unix声明含nullok'
        if any('nullok_secure' in h[5] for h in relevant): return '待核实','未见nullok，但存在不同选项nullok_secure，须单独核对适用条件'
        return '符合','所查pam_unix声明均未见nullok'
    if index==22:
        bad=any(any(t.startswith('remember=') for t in h[5]) for h in relevant)
        return ('不符合' if bad else '符合'),('所查pam_unix含remember；历史功能应由pam_pwhistory承担' if bad else '所查pam_unix声明均未见remember参数')
    algorithms={'md5','bigcrypt','sha256','sha512','yescrypt','blowfish','des','gost_yescrypt'}
    for h in relevant:
        alg=set(h[5]) & algorithms
        if len(alg)>1: return '待核实','同一pam_unix声明存在多个算法参数，未推定优先级'
        if alg=={'yescrypt'}: return '待核实','配置yescrypt；原文要求先确认本机支持，未直接按符合处理'
        if alg!={'sha512'}: return '不符合','所查password类型pam_unix未明确配置原文要求的sha512'
    return '符合','所查password类型pam_unix明确配置sha512；未读取现有账号哈希'

def compact_actual(index,hits):
    mod='pam_pwhistory.so' if index<=20 else 'pam_unix.so'
    selected=[h for h in hits if h[4]==mod and (index in (21,22) or h[2]=='password')]
    if not selected: return '未取得适用'+mod+'声明'
    tokens={18:{'remember'},19:{'enforce_for_root'},20:{'use_authtok'},21:{'nullok','nullok_secure'},22:{'remember'},23:{'md5','bigcrypt','sha256','sha512','yescrypt','blowfish','des','gost_yescrypt'},24:{'use_authtok'}}[index]
    facts=[]
    for h in selected:
        found=[t for t in h[5] if t.split('=',1)[0] in tokens]
        if found: facts.append('{}:{} {} [{}]'.format(h[0],h[1],h[2],','.join(found)))
    if not facts:
        return '{}条适用声明；未见{}'.format(len(selected),'/'.join(sorted(tokens)))
    return '；'.join(facts)

def main():
    if sys.platform != 'linux':
        raise SystemExit('仅在目标Ubuntu运行；未执行任何采集。')
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['LC_ALL'] = 'C'
    os.umask(0o077)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    fd, proof_name = tempfile.mkstemp(prefix='G02_018_024_证据_' + stamp + '_', suffix='.txt', dir='.')
    proof = os.fdopen(fd, 'w', encoding='utf-8', buffering=1)
    q = 0

    def log(title, output, rc):
        nonlocal q
        q += 1
        proof.write('[E-{}] {}\n输出与错误：\n{}\n退出码/读取状态码：{}\n\n'.format(q, title, output, rc))
        return q

    def run(args):
        try:
            p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, encoding='utf-8', errors='replace', timeout=10)
            output, rc = p.stdout, p.returncode
        except subprocess.TimeoutExpired as exc:
            output = '查询超时；' + str(exc.output or '')
            rc = 124
        except FileNotFoundError:
            output, rc = '命令不存在：' + args[0], 127
        except OSError as exc:
            output, rc = str(exc), 1
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
        log('范围及边界', 'G02-018～024；仅读PAM和安全策略配置；不执行sshd/-T/-t/ssh连接，不读取密钥、密码哈希及密码历史。', 0)
        identity, rc = run(['uname', '-s', '-n', '-r', '-m'])
        if rc or identity != 'Linux lab-ubuntu20 5.4.0-216-generic x86_64':
            raise OSError('身份与已确认资产不一致，停止套用基线')
        distro, rc = run(['awk', '/^(ID|VERSION_ID)=/ {print}', '/etc/os-release'])
        if rc or not re.search(r'^ID="?ubuntu"?$', distro, re.M) or not re.search(r'^VERSION_ID="?20\.04"?$', distro, re.M):
            raise OSError('未确认Ubuntu 20.04')


        safe_file(BASE,directory=True)
        cache={}
        def read_config(name):
            if name in cache: return cache[name]
            if len(cache)>=64: return [],['配置文件超过64个上限']
            path=BASE/name
            try:
                safe_file(path)
                if path.stat().st_size>512*1024: raise OSError('PAM配置超过512KiB上限')
                records,errors=parse_config(path.read_text(encoding='utf-8'))
                display=[]
                for typ,kind,control,target,options,line,custom in records:
                    display.append('{}:{}: {} {} {} {}'.format(path,line,kind or '全部类型',control,target,' '.join(options)).rstrip()+(' [自定义模块路径，身份未核实]' if custom else ''))
                log('PAM配置结构：'+str(path),'\n'.join(display) or '未见有效配置声明',0)
                if errors: log('PAM解析缺口：'+str(path),'\n'.join(errors),1)
                cache[name]=(records,errors)
            except (OSError,UnicodeError) as exc:
                log('读取PAM配置失败：'+str(path),str(exc),1)
                cache[name]=([],['读取失败；不推定为空配置，也不自动推定other回退'])
            return cache[name]

        # 沿用已完成的入口追踪结论；本批读取common配置中的新参数，仍自动处理其引用。
        traces={name:trace_service(name,read_config) for name in COMMON}
        all_hits=[]; all_gaps=[]; seen_hits=set()
        for name,(hits,edges,gaps,seen) in traces.items():
            all_gaps.extend(gaps)
            for h in hits:
                sig=(h[0],h[1],h[2],h[4])
                if sig not in seen_hits: all_hits.append(h); seen_hits.add(sig)
        lines=['G02-018～024｜密码历史与pam_unix参数',
               '时间：'+datetime.now().astimezone().isoformat(timespec='seconds'),
               '口径：配置声明对照；沿用此前PAM入口引用补查，未执行改密或认证测试。',
               '只读取PAM配置，不读取/etc/shadow或/etc/security/opasswd，也不查询实际账号哈希。']
        counts={'符合':0,'不符合':0,'待核实':0}
        for index,name,cis,pages,rule in ITEMS:
            hits,gaps=(all_hits,all_gaps) if index in (21,22) else (traces['common-password'][0],traces['common-password'][2])
            verdict,why=assess(index,hits,gaps)
            actual=compact_actual(index,hits)
            if gaps: actual+='；存在覆盖缺口'
            counts[verdict]+=1
            lines+=['','[G02-{:03d}] {} | {}'.format(index,verdict,name),
                    '  基线：CIS '+cis+' / p.'+pages+'；推荐：'+rule,
                    '  实际：'+actual,'  说明：'+why]
        lines+=['','本批统计：'+'；'.join(k+str(v)+'项' for k,v in counts.items()),
                '读取/引用/解析缺口：'+('；'.join(dict.fromkeys(all_gaps)) or '未发现'),
                '不含nullok不证明所有账号都有密码；配置sha512不证明历史账号哈希都已采用sha512。',
                '每个配置文件仅读取一次；本批不重复查询软件包及passwd/sshd/login入口。',
                '详细证据：'+str(Path(proof_name).absolute())]
        fd,summary=tempfile.mkstemp(prefix='G02_018_024_结果_'+stamp+'_',suffix='.txt',dir='.')
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

PY_G02_018_024
