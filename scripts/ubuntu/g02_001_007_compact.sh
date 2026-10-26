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
python3 - <<'PY_G02_001_007'
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



PACKAGES = ['libpam-runtime','libpam-modules','libpam-pwquality']
COMMON = ['common-account','common-auth','common-password','common-session','common-session-noninteractive']
MODULES = {'pam_unix.so','pam_faillock.so','pam_pwquality.so','pam_pwhistory.so','pam_tally2.so','pam_sss.so','pam_ldap.so','pam_winbind.so'}
FLAGS = {'preauth','authfail','authsucc','silent','audit','deny','unlock_time','fail_interval','even_deny_root','root_unlock_time','use_authtok','try_first_pass','use_first_pass','nullok','nullok_secure','sha512','sha256','yescrypt','md5','bigcrypt','obscure','remember','enforce_for_root','retry','minlen','difok','dcredit','ucredit','lcredit','ocredit','minclass','maxrepeat','maxsequence','dictcheck','enforcing'}

def selected_options(text):
    result = []
    for token in text.split():
        key, sep, value = token.partition('=')
        if key in FLAGS and (not sep or re.fullmatch(r'-?\d{1,10}',value)):
            result.append(token)
    return result

def parse_pam(text):
    rows, gaps = [], []
    for n,raw in enumerate(text.splitlines(),1):
        line = raw.split('#',1)[0].strip()
        if not line:
            continue
        if line.startswith('@include'):
            rows.append((n,'include','','',[])); gaps.append('第{}行有外部include，未展开'.format(n)); continue
        m = re.fullmatch(r'(-?(?:auth|account|password|session))\s+(\[[^\]]+\]|\S+)\s+(\S+)(?:\s+(.*))?',line)
        if not m:
            gaps.append('第{}行不能按标准PAM声明解析（未输出原文）'.format(n)); continue
        kind,control,module,args = m[1].lstrip('-'),m[2],m[3],m[4] or ''
        if control in ('include','substack'):
            gaps.append('第{}行有include/substack，未展开'.format(n))
        name = Path(module).name
        if '/' in module:
            gaps.append('第{}行使用自定义模块路径，未确认模块身份'.format(n))
        if '\\' in args or '"' in args or "'" in args:
            gaps.append('第{}行含复杂参数/续行，未完整解析'.format(n))
        options = selected_options(args) if name in MODULES else []
        rows.append((n,kind,control,name,options))
    return rows,gaps

def assess_module(index, data, errors):
    files = COMMON if index==4 else ['common-auth','common-account'] if index==5 else ['common-password']
    if any(errors.get(f) for f in files):
        return '待核实','所需配置读取/解析存在缺口，见证据'
    if index==4:
        expected = dict(zip(COMMON,['account','auth','password','session','session']))
        missing = [f for f in files if not any(r[1]==expected[f] and r[3]=='pam_unix.so' for r in data[f])]
        return ('不符合','未见pam_unix有效声明：'+','.join(missing)) if missing else ('符合','5个common文件均见对应类型的pam_unix声明')
    if index==5:
        auth = [r for r in data['common-auth'] if r[1]=='auth' and r[3]=='pam_faillock.so']
        account = [r for r in data['common-account'] if r[1]=='account' and r[3]=='pam_faillock.so']
        if not auth and not account:
            tally = any(r[3]=='pam_tally2.so' for f in files for r in data[f])
            return '不符合','未见pam_faillock声明'+('；存在pam_tally2，不能直接代替本条要求' if tally else '')
        pre = any('preauth' in r[4] for r in auth)
        fail = any('authfail' in r[4] for r in auth)
        if pre and fail and account:
            return '符合','auth含preauth/authfail；account含pam_faillock；仅判模块声明接入'
        return '待核实','存在pam_faillock，但接入方式与原文示例不同：preauth={}，authfail={}，account={}'.format(pre,fail,bool(account))
    module = 'pam_pwquality.so' if index==6 else 'pam_pwhistory.so'
    found = [r for r in data['common-password'] if r[1]=='password' and r[3]==module]
    if not found:
        return '不符合','common-password未见'+module+'有效声明'
    if any(r[2] in ('required','requisite') for r in found):
        return '符合','common-password已声明'+module+'；control='+','.join(r[2] for r in found)
    return '待核实','存在模块声明，但控制字段需核对：'+','.join(r[2] for r in found)

def package_filter(output, rc):
    if rc:
        return re.sub(r'\b(?:https?|ftp)://\S+','[URL已隐藏]',output)
    return '\n'.join(line for line in output.splitlines() if line.split('\t')[0].split(':')[0] in PACKAGES)

def policy_filter(output, rc):
    selected=[]
    for line in output.splitlines():
        if re.fullmatch(r'\s*(?:Installed|Candidate):\s*\S+\s*',line):
            selected.append(line.strip())
        elif line.startswith(('E:','W:')) or rc:
            selected.append(re.sub(r'\b(?:https?|ftp)://\S+','[URL已隐藏]',line))
    return '\n'.join(selected)

def main():
    if sys.platform != 'linux':
        raise SystemExit('仅在目标Ubuntu运行；未执行任何采集。')
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['LC_ALL'] = 'C'
    os.umask(0o077)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    fd, proof_name = tempfile.mkstemp(prefix='G02_001_007_证据_' + stamp + '_', suffix='.txt', dir='.')
    proof = os.fdopen(fd, 'w', encoding='utf-8', buffering=1)
    q = 0

    def log(title, output, rc):
        nonlocal q
        q += 1
        proof.write('[E-{}] {}\n输出与错误：\n{}\n退出码/读取状态码：{}\n\n'.format(q, title, output, rc))
        return q

    def run(args, output_filter=None):
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
        if output_filter is not None:
            output = output_filter(output, rc)
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
        log('范围及边界', 'G02-001～007；仅读PAM配置、包数据库及本地APT缓存；不执行sshd/-T/-t/ssh连接，不读取密钥、密码哈希及密码历史。', 0)
        identity, rc = run(['uname', '-s', '-n', '-r', '-m'])
        if rc or identity != 'Linux lab-ubuntu20 5.4.0-216-generic x86_64':
            raise OSError('身份与已确认资产不一致，停止套用基线')
        distro, rc = run(['awk', '/^(ID|VERSION_ID)=/ {print}', '/etc/os-release'])
        if rc or not re.search(r'^ID="?ubuntu"?$', distro, re.M) or not re.search(r'^VERSION_ID="?20\.04"?$', distro, re.M):
            raise OSError('未确认Ubuntu 20.04')

        # 包记录一次读取，输出仅保留本批三个包；rc=0且无记录才判包未安装。
        packages, rc = run(['dpkg-query','-W','-f=${binary:Package}\t${Version}\t${Status}\n'], package_filter)
        pkg_error = rc != 0
        installed = {}
        for row in packages.splitlines():
            fields=row.split('\t')
            if len(fields)==3:
                installed[fields[0].split(':')[0]]=(fields[1],fields[2])
        cache_ok=False
        cache_note='未取得本地APT索引时间'
        try:
            cache=Path('/var/lib/apt/lists')
            safe_file(cache,directory=True)
            entries=[]
            for p in cache.iterdir():
                if p.name.endswith(('_InRelease','_Release')):
                    s=p.lstat()
                    if stat.S_ISREG(s.st_mode): entries.append(s.st_mtime)
            if entries:
                cache_ok=True
                cache_note='现存Release索引mtime范围：'+datetime.fromtimestamp(min(entries)).astimezone().isoformat(timespec='seconds')+' 至 '+datetime.fromtimestamp(max(entries)).astimezone().isoformat(timespec='seconds')
            else:
                cache_note='未找到Release索引元数据，不能确认本地缓存版本范围'
            log('只读APT索引元数据；mtime不是成功更新证明',cache_note,0)
        except OSError as exc:
            log('读取APT索引元数据',str(exc),1)
        results=[]
        titles=['PAM运行时软件包','PAM模块软件包','密码质量软件包']
        pages=['563–564','565–566','567–569']
        for index,pkg in enumerate(PACKAGES,1):
            info=installed.get(pkg)
            if pkg_error:
                decision,actual='待核实','包数据库查询失败，不能判断是否安装'
            elif not info or info[1].split()[-2:]!=['ok','installed']:
                decision,actual='不符合','dpkg成功查询；'+('未见该包记录' if not info else '状态='+info[1])+'；未满足指定包已安装要求'
            else:
                # 禁用磁盘缓存写入；只读本地索引，不联网、不更新索引。
                policy,prc=run(['apt-cache','-o','Dir::Cache::pkgcache=','-o','Dir::Cache::srcpkgcache=','policy',pkg],policy_filter)
                match=re.search(r'^Candidate:\s*(\S+)',policy,re.M)
                candidate=match[1] if match else None
                actual='已安装='+info[0]+'；本地APT候选='+(candidate or '未取得')
                if prc or not cache_ok or candidate in (None,'(none)') or any(line.startswith(('E:','W:')) for line in policy.splitlines()):
                    decision='待核实'
                else:
                    _,cmp=run(['dpkg','--compare-versions',info[0],'eq',candidate])
                    if cmp==0:
                        decision='符合（本地缓存对照）'
                    elif cmp==1:
                        _,older=run(['dpkg','--compare-versions',info[0],'lt',candidate])
                        decision='不符合' if older==0 else '待核实'
                        actual+='；'+('本地缓存存在较新候选' if older==0 else '版本关系需要核对')
                    else:
                        decision='待核实'
            results.append((index,titles[index-1],'5.3.1.'+str(index),'p.'+pages[index-1],'指定包已安装；采用最新可用版本',actual,decision))
        data,errors={},{}
        for filename in COMMON:
            path=Path('/etc/pam.d')/filename
            data[filename]=[]; errors[filename]=[]
            try:
                safe_file(path)
                if path.stat().st_size>1024*1024:
                    raise OSError('PAM配置超过1MiB上限')
                data[filename],errors[filename]=parse_pam(path.read_text(encoding='utf-8'))
                # 保留全部模块顺序与控制字段；只输出已知的非敏感安全参数，不输出任意模块参数。
                excerpt=['{}:{}: {} {} {} {}'.format(path,r[0],r[1],r[2],r[3],' '.join(r[4])).rstrip() for r in data[filename]]
                log('PAM配置结构（参数白名单）：'+str(path),'\n'.join(excerpt) or '没有有效PAM声明',0)
                if errors[filename]: log('解析缺口：'+filename,'；'.join(errors[filename]),1)
            except (OSError,UnicodeError) as exc:
                errors[filename]=[str(exc)]; log('读取PAM配置失败：'+filename,str(exc),1)
        names={4:'pam_unix接入',5:'pam_faillock接入',6:'pam_pwquality接入',7:'pam_pwhistory接入'}
        pages2={4:'570–571',5:'572–574',6:'575–577',7:'578–582'}
        rules={4:'5个common文件启用对应类型的pam_unix',5:'auth/account接入pam_faillock',6:'password接入pam_pwquality',7:'password接入pam_pwhistory'}
        for index in range(4,8):
            verdict,actual=assess_module(index,data,errors)
            results.append((index,names[index],'5.3.2.'+str(index-3),'p.'+pages2[index],rules[index],actual,verdict))
        lines=['G02-001～007｜PAM软件包与模块接入',
               '时间：'+datetime.now().astimezone().isoformat(timespec='seconds'),
               '口径：包版本只对照现存APT候选；模块只对照配置声明，不执行认证或改密测试。',
               'APT缓存未联网刷新，缓存相同不证明当前在线最新或全部补丁合规；候选也可能受源和优先级限制。',
               cache_note]
        for index,name,cis,page,rule,actual,verdict in results:
            lines+=['','[G02-{:03d}] {} | {}'.format(index,verdict,name),'  基线：CIS '+cis+' / '+page+'；推荐：'+rule,'  实际：'+actual]
        counts={'符合':0,'不符合':0,'待核实':0}
        for r in results:
            counts['符合' if r[-1].startswith('符合') else r[-1]]+=1
        lines+=['','本批统计：'+'；'.join(k+str(v)+'项' for k,v in counts.items()),
                '配置模块存在不等于模块运行成功、控制流无绕过或整个密码策略合规；后续按领域条目继续。',
                '本批未读取shadow、密码历史或任何密码哈希。',
                '详细证据：'+str(Path(proof_name).absolute())]
        fd,summary=tempfile.mkstemp(prefix='G02_001_007_结果_'+stamp+'_',suffix='.txt',dir='.')
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            f.write('\n'.join(lines)+'\n')
        print('\n'.join(lines)); print('\n简明结果：'+str(Path(summary).absolute()))
    except (OSError,UnicodeError,KeyboardInterrupt) as exc:
        log('停止；本批不完整',str(exc),1)
        print('已停止：{}\n保留证据：{}'.format(exc,Path(proof_name).absolute()),file=sys.stderr)
        return 2
    finally:
        proof.close()
    return 0

if __name__=='__main__':
    sys.exit(main())

PY_G02_001_007
