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
python3 - <<'PY_G02_008_017'
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



ITEMS=[
 (8,'失败锁定次数','5.3.3.1.1','583–584',['deny'],'deny为1～5'),
 (9,'自动解锁时间','5.3.3.1.2','585–587',['unlock_time'],'unlock_time为0或900～604800秒'),
 (10,'新旧密码不同字符数','5.3.3.2.1','593–595',['difok'],'difok≥2'),
 (11,'最小密码长度','5.3.3.2.2','596–599',['minlen'],'minlen≥14'),
 (12,'密码复杂度','5.3.3.2.3','600–603',['minclass','dcredit','ucredit','lcredit','ocredit'],'各credit≤0；字符类别要求符合本地策略（Manual）'),
 (13,'相同字符连续次数','5.3.3.2.4','604–607',['maxrepeat'],'maxrepeat为1～3'),
 (14,'连续序列长度','5.3.3.2.5','608–611',['maxsequence'],'maxsequence为1～3'),
 (15,'字典检查','5.3.3.2.6','612–614',['dictcheck'],'不禁用dictcheck（不能为0）'),
 (16,'强制密码质量检查','5.3.3.2.7','615–616',['enforcing'],'不禁用enforcing（不能为0）'),
 (17,'root执行密码质量检查','5.3.3.2.8','617–620',['enforce_for_root'],'启用enforce_for_root'),
]
KEYS={k for row in ITEMS for k in row[4]}

def parse_settings(text,source):
    values={}; evidence=[]; errors=[]
    for n,raw in enumerate(text.splitlines(),1):
        line=raw.split('#',1)[0].strip()
        if not line: continue
        key=re.split(r'[\s=]',line,maxsplit=1)[0]
        if key not in KEYS: continue
        origin='{}:{}'.format(source,n)
        if line=='enforce_for_root':
            values[key]=(1,origin); evidence.append(origin+': enforce_for_root'); continue
        match=re.fullmatch(r'([a-z_]+)\s*=\s*(-?\d{1,9})',line)
        if not match or key=='enforce_for_root':
            errors.append(origin+': 参数写法未支持，原值未输出'); continue
        values[key]=(int(match[2]),origin)
        evidence.append(origin+': '+key+'='+match[2])
    return values,evidence,errors

def parse_pam(text,source):
    modules=[]; notes=[]; errors=[]
    for n,raw in enumerate(text.splitlines(),1):
        line=raw.split('#',1)[0].strip()
        if not line: continue
        origin='{}:{}'.format(source,n)
        if line.startswith('@include'):
            errors.append(origin+': 存在include，未展开'); continue
        m=re.fullmatch(r'(-?(?:auth|account|password|session))\s+(\[[^\]]+\]|\S+)\s+(\S+)(?:\s+(.*))?',line)
        if not m:
            errors.append(origin+': PAM结构未识别，原文未输出'); continue
        kind,control,module,args=m[1].lstrip('-'),m[2],m[3],m[4] or ''
        if control in ('include','substack'):
            errors.append(origin+': 存在include/substack，未展开'); continue
        name=Path(module).name
        if name not in ('pam_faillock.so','pam_pwquality.so'): continue
        if '/' in module or '\\' in args or '"' in args or "'" in args or re.search(r'\bconf\s*=',args):
            errors.append(origin+': 自定义模块/配置路径或复杂参数，未展开')
        opts={}; phases=[]
        for token in ('preauth','authfail','authsucc','enforce_for_root'):
            if re.search(r'(?:^|\s)'+token+r'(?:\s|$)',args):
                if token=='enforce_for_root': opts[token]=(1,origin+' [PAM参数]')
                else: phases.append(token)
        for key in KEYS-{'enforce_for_root'}:
            found=list(re.finditer(r'(?:^|\s)'+key+r'\s*=\s*(\S+)',args))
            for hit in found:
                if re.fullmatch(r'-?\d{1,9}',hit[1]): opts[key]=(int(hit[1]),origin+' [PAM参数]')
                else: errors.append(origin+': '+key+'参数无法解析')
        if re.search(r'\benforce_for_root\s*=',args): errors.append(origin+': enforce_for_root应为开关，赋值写法未解释')
        modules.append((kind,control,name,opts,phases,origin))
        notes.append(origin+': '+kind+' '+control+' '+name+' '+' '.join(phases+['{}={}'.format(k,v[0]) for k,v in opts.items()]))
    return modules,notes,errors

def assess(index,values,module_state,has_gap):
    module='pam_faillock' if index in (8,9) else 'pam_pwquality'
    if module_state is False:
        return '不符合',module+'未接入，所查策略未通过该模块落实'
    if module_state is None or has_gap:
        return '待核实','配置读取/解析或模块接入存在缺口'
    if index==12:
        credits=[values.get(k,(None,''))[0] for k in ('dcredit','ucredit','lcredit','ocredit')]
        if any(v is not None and v>0 for v in credits): return '不符合','存在大于0的credit，不满足原文要求'
        return '待人工确认','未发现显式正credit；本地字符类别策略尚未确认，不能套用示例判符合'
    key=next(row[4][0] for row in ITEMS if row[0]==index)
    value=values.get(key,(None,''))[0]
    if index in (15,16):
        if value is None: return '符合','按原文审计口径，未见该参数的禁用声明'
        good=value!=0
    elif index==17:
        good=value==1
    elif value is None:
        return '待核实','未取得显式参数值；本批未推定该数值默认值'
    elif index==8: good=1<=value<=5
    elif index==9: good=value==0 or 900<=value<=604800
    elif index==10: good=value>=2
    elif index==11: good=value>=14
    else: good=1<=value<=3
    why='所查配置'+('满足' if good else '不满足')+'本项要求'
    if index==9 and value==0: why+='；0表示不按时间自动解锁，本次不执行解锁'
    return ('符合' if good else '不符合'),why

def main():
    if sys.platform != 'linux':
        raise SystemExit('仅在目标Ubuntu运行；未执行任何采集。')
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['LC_ALL'] = 'C'
    os.umask(0o077)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    fd, proof_name = tempfile.mkstemp(prefix='G02_008_017_证据_' + stamp + '_', suffix='.txt', dir='.')
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
        log('范围及边界', 'G02-008～017；仅读PAM和安全策略配置；不执行sshd/-T/-t/ssh连接，不读取密钥、密码哈希及密码历史。', 0)
        identity, rc = run(['uname', '-s', '-n', '-r', '-m'])
        if rc or identity != 'Linux lab-ubuntu20 5.4.0-216-generic x86_64':
            raise OSError('身份与已确认资产不一致，停止套用基线')
        distro, rc = run(['awk', '/^(ID|VERSION_ID)=/ {print}', '/etc/os-release'])
        if rc or not re.search(r'^ID="?ubuntu"?$', distro, re.M) or not re.search(r'^VERSION_ID="?20\.04"?$', distro, re.M):
            raise OSError('未确认Ubuntu 20.04')

        data={}; evidence=[]; family_errors={'faillock':[],'quality':[]}
        pam_modules=[]; pam_errors={}
        for filename in ('common-auth','common-account','common-password'):
            path=Path('/etc/pam.d')/filename
            try:
                safe_file(path)
                if path.stat().st_size>1024*1024: raise OSError('配置超过1MiB上限')
                mods,notes,errors=parse_pam(path.read_text(encoding='utf-8'),str(path))
                pam_modules.extend(mods); pam_errors[filename]=errors
                log('PAM必要字段：'+str(path),'\n'.join(notes) or '未见pam_faillock/pam_pwquality有效声明',0)
                if errors: log('PAM解析缺口', '\n'.join(errors),1)
            except (OSError,UnicodeError) as exc:
                pam_errors[filename]=[str(exc)]; log('PAM读取失败：'+str(path),str(exc),1)
        lock=[r for r in pam_modules if r[2]=='pam_faillock.so' and r[0] in ('auth','account')]
        quality=[r for r in pam_modules if r[2]=='pam_pwquality.so' and r[0]=='password']
        if pam_errors['common-auth'] or pam_errors['common-account']:
            lock_state=None
        elif not lock: lock_state=False
        else:
            pre=any(r[0]=='auth' and 'preauth' in r[4] for r in lock)
            fail=any(r[0]=='auth' and 'authfail' in r[4] for r in lock)
            account=any(r[0]=='account' for r in lock)
            lock_state=True if pre and fail and account else None
        quality_state=None if pam_errors['common-password'] else False if not quality else True if len(quality)==1 and quality[0][1] in ('required','requisite') else None
        # 查询可选策略文件。明确不存在与权限/查询错误分开记录；不把缺失文件当成默认值。
        def read_policy(path,family):
            try:
                safe_file(path.parent,directory=True)
                try: path.lstat()
                except FileNotFoundError:
                    log('可选配置：'+str(path),'文件不存在；未取得显式配置，不据此推定默认值',2)
                    return {}
                safe_file(path)
                if path.stat().st_size>1024*1024: raise OSError('配置超过1MiB上限')
                vals,notes,errors=parse_settings(path.read_text(encoding='utf-8'),str(path))
                family_errors[family].extend(errors)
                log('策略白名单字段：'+str(path),'\n'.join(notes) or '未见本批显式参数',0)
                if errors: log('策略解析缺口','\n'.join(errors),1)
                return vals
            except (OSError,UnicodeError) as exc:
                family_errors[family].append(str(exc)); log('读取失败：'+str(path),str(exc),1); return {}
        lock_values=read_policy(Path('/etc/security/faillock.conf'),'faillock')
        quality_values={}
        directory=Path('/etc/security/pwquality.conf.d')
        try:
            safe_file(directory.parent,directory=True)
            try: directory.lstat()
            except FileNotFoundError: log('可选片段目录',str(directory)+'不存在',2)
            else:
                safe_file(directory,directory=True)
                snippets=sorted(directory.glob('*.conf'),key=lambda p:os.fsencode(p.name))
                if len(snippets)>64: raise OSError('pwquality配置片段超过64个上限')
                for path in snippets: quality_values.update(read_policy(path,'quality'))
        except OSError as exc:
            family_errors['quality'].append(str(exc)); log('片段目录读取失败',str(exc),1)
        # 原文顺序：片段按文件名顺序读取，主文件覆盖片段，PAM模块参数最后覆盖。
        quality_values.update(read_policy(Path('/etc/security/pwquality.conf'),'quality'))
        # 多次faillock调用中不同的显式值不可盲目按最后一行覆盖。
        for key in ('deny','unlock_time'):
            args=[r[3][key] for r in lock if key in r[3]]
            if args:
                possible={r[3].get(key,lock_values.get(key,(None,'')))[0] for r in lock}
                if len(possible)!=1:
                    family_errors['faillock'].append(key+'在各faillock调用中的值不同或未确定')
                else: lock_values[key]=args[0]
        if len(quality)==1: quality_values.update(quality[0][3])
        lines=['G02-008～017｜失败锁定与密码质量',
               '时间：'+datetime.now().astimezone().isoformat(timespec='seconds'),
               '口径：按配置声明对照；仅查必要参数与模块接入，不测试登录、失败锁定或修改密码。',
               '上一批已查模块缺失；本次顺带核对PAM参数覆盖关系，不重复查询软件包。']
        counts={'符合':0,'不符合':0,'待核实':0,'待人工确认':0}
        for index,name,cis,pages,keys,rule in ITEMS:
            family='faillock' if index<10 else 'quality'
            values=lock_values if index<10 else quality_values
            state=lock_state if index<10 else quality_state
            verdict,why=assess(index,values,state,bool(family_errors[family]))
            actual=[]
            for key in keys:
                if key in values:
                    val,source=values[key]
                    actual.append(key+('已配置' if key=='enforce_for_root' else '='+str(val))+' ['+source+']')
                else: actual.append(key+('未确定（读取/解析缺口）' if family_errors[family] else '未见显式设置'))
            counts[verdict]+=1
            lines+=['','[G02-{:03d}] {} | {}'.format(index,verdict,name),
                    '  基线：CIS '+cis+' / p.'+pages+'；推荐：'+rule,
                    '  实际：'+'；'.join(actual),'  说明：'+why]
        lines+=['','本批统计：'+'；'.join(k+str(v)+'项' for k,v in counts.items()),
                '额外读取/解析缺口：'+('；'.join(family_errors['faillock']+family_errors['quality']+[e for es in pam_errors.values() for e in es]) or '未发现'),
                '因模块未接入判不符合的条目是同一前置缺失影响的多个控制项，不代表发生了多个独立故障。',
                '详细证据：'+str(Path(proof_name).absolute())]
        fd,summary=tempfile.mkstemp(prefix='G02_008_017_结果_'+stamp+'_',suffix='.txt',dir='.')
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

PY_G02_008_017
