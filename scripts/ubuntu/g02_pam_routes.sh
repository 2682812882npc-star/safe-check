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
python3 - <<'PY_G02_PAM_ROUTES'
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
FLAGS={'preauth','authfail','authsucc','enforce_for_root','even_deny_root','use_authtok','try_first_pass','nullok','nullok_secure','sha512','yescrypt'}

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

def main():
    if sys.platform != 'linux':
        raise SystemExit('仅在目标Ubuntu运行；未执行任何采集。')
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['LC_ALL'] = 'C'
    os.umask(0o077)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    fd, proof_name = tempfile.mkstemp(prefix='G02_PAM引用补查_证据_' + stamp + '_', suffix='.txt', dir='.')
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
        log('范围及边界', 'PAM引用关系补查；仅读PAM和安全策略配置；不执行sshd/-T/-t/ssh连接，不读取密钥、密码哈希及密码历史。', 0)
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
        lines=['G02｜PAM入口引用关系补查',
               '时间：'+datetime.now().astimezone().isoformat(timespec='seconds'),
               '范围：passwd、sshd、login及其配置引用；不代表所有应用入口。',
               '口径：只追踪配置声明，不模拟控制字段跳转，也不证明模块实际执行；不加载任何PAM模块。']
        all_hits=[]; all_gaps=[]
        entries=[('passwd','密码修改入口'),('sshd','SSH认证及改密配置入口'),('login','本地登录配置入口')]
        for index,(entry,label) in enumerate(entries,1):
            hits,edges,gaps,seen=trace_service(entry,read_config)
            all_hits.extend(hits); all_gaps.extend(gaps)
            lines+=['','[PAM-{:02d}] {} | {}'.format(index,entry,label),
                    '  引用：'+('；'.join(edges) or '未发现可解析的引用'),
                    '  覆盖：'+str(len({s[0] for s in seen}))+'个文件；缺口：'+('；'.join(gaps) or '未发现')]
            for module in ('pam_pwquality.so','pam_faillock.so'):
                found=[h for h in hits if h[4]==module]
                fact='；'.join('{}:{} {} {} {}'.format(h[0],h[1],h[2],h[3],' '.join(h[5])).rstrip()+(' [自定义模块路径]' if h[6] else '') for h in found)
                lines+=['  '+module+'：'+(fact or ('未见声明，但存在覆盖缺口，不能确认缺失' if gaps else '所查引用中未见声明'))]
            clues=[h for h in hits if h[4] in ALTERNATIVES|EXTERNAL|DYNAMIC]
            lines+=['  其他机制线索：'+('；'.join('{}:{} {} {}'.format(h[0],h[1],h[2],h[4]) for h in clues) or '未见所列替代/外部认证模块声明')]
        lines+=['','补查结论：']
        for module,items in [('pam_faillock.so','G02-008～009'),('pam_pwquality.so','G02-010～017')]:
            found=[h for h in all_hits if h[4]==module]
            if found: text=items+'：发现模块声明；回传后核对类型、控制字段及参数，不自动改判符合。'
            elif all_gaps: text=items+'：尚有引用/读取缺口，保留已有公共配置范围结论。'
            else: text=items+'：三个所查入口及其引用均未见该模块；支持保留所查范围不符合结论。'
            lines.append('  '+text)
        lines+=['发现其他认证/质量模块只表示线索，不自动等同CIS要求已满足。',
                '未引用的配置文件、其他服务入口和外部认证平台不在本次覆盖范围；未发起外部连接。',
                '实际读取配置文件数：'+str(len(cache))+'；同一文件只读取一次。',
                '详细证据：'+str(Path(proof_name).absolute())]
        fd,summary=tempfile.mkstemp(prefix='G02_PAM引用补查_结果_'+stamp+'_',suffix='.txt',dir='.')
        with os.fdopen(fd,'w',encoding='utf-8') as f: f.write('\n'.join(lines)+'\n')
        print('\n'.join(lines)); print('\n简明结果：'+str(Path(summary).absolute()))
    except (OSError,UnicodeError,KeyboardInterrupt) as exc:
        log('停止；引用补查不完整',str(exc),1)
        print('已停止：{}\n保留证据：{}'.format(exc,Path(proof_name).absolute()),file=sys.stderr)
        return 2
    finally:
        proof.close()
    return 0

if __name__=='__main__': sys.exit(main())

PY_G02_PAM_ROUTES
