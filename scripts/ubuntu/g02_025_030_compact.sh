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
python3 - <<'PY_G02_025_030'
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
 (25,'密码最长有效期','5.4.1.1','643–645','PASS_MAX_DAYS为1～365天；已有适用账号也应满足'),
 (26,'密码到期提醒','5.4.1.3','649–650','PASS_WARN_AGE≥7天；已有适用账号也应满足'),
 (27,'默认密码哈希算法配置','5.4.1.4','651–653','ENCRYPT_METHOD为SHA512或YESCRYPT'),
 (28,'密码过期后失效锁定','5.4.1.5','654–655','INACTIVE为0～45天；已有适用账号也应满足'),
 (29,'最近改密日期','5.4.1.6','656–658','适用账号最近改密日期不得在未来'),
 (30,'账号空口令字段','7.2.2','896–897','/etc/shadow密码字段不为空；账号应有密码或被锁定'),
]

def parse_defaults(text,source,assignment=False):
    allowed={'INACTIVE'} if assignment else {'PASS_MAX_DAYS','PASS_WARN_AGE','PASS_MIN_DAYS','ENCRYPT_METHOD'}
    values={k:[] for k in allowed}; errors={}; notes=[]
    for n,raw in enumerate(text.splitlines(),1):
        line=raw.split('#',1)[0].strip()
        if not line: continue
        key=re.split(r'[\s=]',line,maxsplit=1)[0]
        if key not in allowed: continue
        origin='{}:{}'.format(source,n)
        pattern=r'([A-Z_]+)\s*=\s*(.*?)\s*' if assignment else r'([A-Z_]+)\s+(.*?)\s*'
        match=re.fullmatch(pattern,line)
        if not match:
            errors[key]=origin+': 参数格式未识别'; continue
        value=match[2]
        if assignment and len(value)>=2 and value[0]==value[-1] and value[0] in (chr(34),chr(39)):
            value=value[1:-1]
        valid=re.fullmatch(r'[A-Za-z0-9_]{1,24}',value) if key=='ENCRYPT_METHOD' else re.fullmatch(r'-?\d{1,9}',value)
        if not valid:
            errors[key]=origin+': 值无法按预期类型解析，原值未输出'; continue
        values[key].append((value,origin))
        notes.append(origin+': '+key+'='+value)
    result={}
    for key,entries in values.items():
        if len({v for v,s in entries})>1: errors[key]='同一文件中存在不同'+key+'声明，未推定覆盖顺序'
        elif entries: result[key]=entries[-1]
    return result,errors,notes

def assess(index,values,errors):
    if index in (29,30):
        return '受限未检查', '未读取账号数据', '当前禁止读取密码哈希；本批不读取shadow，不推定结果'
    key={25:'PASS_MAX_DAYS',26:'PASS_WARN_AGE',27:'ENCRYPT_METHOD',28:'INACTIVE'}[index]
    if errors.get('*') or errors.get(key):
        return '待核实', key+'未确定', errors.get('*') or errors[key]
    if key not in values:
        return '待核实',key+'未见显式设置','没有取得参数值；本批不推定缺省值'
    value,source=values[key]
    actual=key+'='+value+' ['+source+']'
    if index==25 and errors.get('PASS_MIN_DAYS'):
        return '待核实',actual,'最小改密间隔解析失败，未确认与最长有效期的关系'
    if index==27:
        good=value.upper() in ('SHA512','YESCRYPT')
        return ('符合' if good else '不符合'),actual,('算法配置满足本条要求；不证明已有账号哈希算法' if good else '算法配置不满足本条要求')
    numeric=int(value)
    good=1<=numeric<=365 if index==25 else numeric>=7 if index==26 else 0<=numeric<=45
    if index==25 and 'PASS_MIN_DAYS' in values and int(values['PASS_MIN_DAYS'][0])>=numeric:
        good=False
        actual+='；PASS_MIN_DAYS='+values['PASS_MIN_DAYS'][0]
    verdict='符合（仅默认配置）' if good else '不符合（默认配置）'
    why='默认值'+('满足' if good else '不满足')+'所查要求；已有账号实际策略受限未检查'
    if index==28 and numeric==-1: why+='；-1未设置密码过期后的失效期限'
    if index==28 and numeric==0: why+='；0表示密码过期后无额外宽限期'
    return verdict,actual,why

def main():
    if sys.platform != 'linux':
        raise SystemExit('仅在目标Ubuntu运行；未执行任何采集。')
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['LC_ALL'] = 'C'
    os.umask(0o077)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    fd, proof_name = tempfile.mkstemp(prefix='G02_025_030_证据_' + stamp + '_', suffix='.txt', dir='.')
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
        log('范围及边界', 'G02-025～030；仅读login.defs和useradd默认配置；不执行sshd/-T/-t/ssh连接，不读取密钥、密码哈希及密码历史。', 0)
        identity, rc = run(['uname', '-s', '-n', '-r', '-m'])
        if rc or identity != 'Linux lab-ubuntu20 5.4.0-216-generic x86_64':
            raise OSError('身份与已确认资产不一致，停止套用基线')
        distro, rc = run(['awk', '/^(ID|VERSION_ID)=/ {print}', '/etc/os-release'])
        if rc or not re.search(r'^ID="?ubuntu"?$', distro, re.M) or not re.search(r'^VERSION_ID="?20\.04"?$', distro, re.M):
            raise OSError('未确认Ubuntu 20.04')


        parsed={}; issues={}
        for path,assignment in [(Path('/etc/login.defs'),False),(Path('/etc/default/useradd'),True)]:
            try:
                safe_file(path)
                if path.stat().st_size>1024*1024: raise OSError('配置文件超过1MiB读取上限')
                values,errors,notes=parse_defaults(path.read_text(encoding='utf-8'),str(path),assignment)
                parsed[str(path)]=values; issues[str(path)]=errors
                log('默认配置白名单字段：'+str(path),'\n'.join(notes) or '未见本批显式设置',0)
                if errors: log('参数解析缺口：'+str(path),'；'.join(errors.values()),1)
            except (OSError,UnicodeError) as exc:
                parsed[str(path)]={}; issues[str(path)]={'*':str(exc)}
                log('读取配置失败：'+str(path),str(exc),1)
        lines=['G02-025～030｜有效期及账号数据范围',
               '时间：'+datetime.now().astimezone().isoformat(timespec='seconds'),
               '口径：025/026/028只检查默认配置，已有账号部分受限；027检查算法配置；029/030受限未检查。',
               '不读取/etc/shadow、gshadow、opasswd；不调用账号密码/改密状态查询，不运行认证或改密测试。']
        counts={'默认配置符合（账号部分未查）':0,'符合':0,'不符合':0,'待核实':0,'受限未检查':0}
        for index,name,cis,pages,rule in ITEMS:
            path='/etc/default/useradd' if index==28 else '/etc/login.defs'
            verdict,actual,why=assess(index,parsed[path],issues[path])
            bucket='默认配置符合（账号部分未查）' if verdict=='符合（仅默认配置）' else '不符合' if verdict.startswith('不符合') else verdict
            counts[bucket]+=1
            lines+=['','[G02-{:03d}] {} | {}'.format(index,verdict,name),
                    '  基线：CIS '+cis+' / p.'+pages+'；推荐：'+rule,
                    '  实际：'+actual,'  说明：'+why]
        lines+=['','本批统计：'+'；'.join(k+str(v)+'项' for k,v in counts.items()),
                '已有账号未查部分：G02-025、026、028；整项受限未查：G02-029、030。',
                'INACTIVE是密码过期后宽限天数，不是多久没有登录；ENCRYPT_METHOD不替代PAM算法设置。',
                '这是第二组最后一批的范围记录，不能把受限未检查计为符合或整组全部核验完成。',
                '详细证据：'+str(Path(proof_name).absolute())]
        fd,summary=tempfile.mkstemp(prefix='G02_025_030_结果_'+stamp+'_',suffix='.txt',dir='.')
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

PY_G02_025_030
