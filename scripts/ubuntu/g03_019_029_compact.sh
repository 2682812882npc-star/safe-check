#!/usr/bin/env bash
# 仅由用户在目标Ubuntu既有root终端运行；不自动提权、不执行配置文件。
if [[ ! -x /usr/bin/python3 ]]; then
  printf '%s\n' '缺少/usr/bin/python3，未执行检查；不自动安装。' >&2
  exit 127
fi
/usr/bin/python3 -I - <<'G03_PY'
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





import collections
import posixpath
import time

ITEMS = [
    (19, '默认Shell超时', '5.4.3.2', '679–682', 'TMOUT为1～900秒；readonly且export'),
    (20, '默认用户umask', '5.4.3.3', '683–687', '0027或更严格；文件不宽于0640，目录不宽于0750'),
    (21, '账号使用影子口令', '7.2.1', '893–895', '/etc/passwd的口令字段均为x；不输出该字段'),
    (22, '账号主组存在', '7.2.3', '898–899', '账号主GID均存在于/etc/group'),
    (23, 'shadow组成员', '7.2.4', '900–901', '无附加成员；无账号以shadow为主组'),
    (24, 'UID唯一', '7.2.5', '902–903', '本地账号UID不重复'),
    (25, 'GID唯一', '7.2.6', '904–905', '本地组GID不重复'),
    (26, '用户名唯一', '7.2.7', '906–907', '本地用户名不重复'),
    (27, '组名唯一', '7.2.8', '908–909', '本地组名不重复'),
    (28, '交互账号家目录', '7.2.9', '910–913', '目录存在、属主为本人；权限不宽于0750'),
    (29, '交互账号隐藏文件', '7.2.10', '914–917', '属主/组为本人/主组；普通隐藏文件≤0644；历史文件≤0600；特殊文件见说明'),
]

# 只输出经过筛选的账号字段。第二字段仅在awk中比较，不打印其内容。
ACCOUNT_AWK = r'''BEGIN {OFS=":"}
NF != 7 || $1 == "" || $3 !~ /^[0-9]+$/ || $4 !~ /^[0-9]+$/ {bad++; next}
{print $1,$3,$4,$6,$7,($2=="x" ? "shadowed" : "not-shadowed")}
END {if(bad) {print "ERROR malformed-record-count=" bad; exit 2}}'''
GROUP_AWK = r'''BEGIN {OFS=":"}
NF != 4 || $1 == "" || $3 !~ /^[0-9]+$/ {bad++; next}
{print $1,$3,$4}
END {if(bad) {print "ERROR malformed-record-count=" bad; exit 2}}'''


def brief(values, limit=3):
    return '；'.join(values[:limit]) + ('；另{}条见证据'.format(len(values)-limit) if len(values)>limit else '')


def result(bad, gaps, success):
    if bad:
        return '不符合', brief(bad), '另有覆盖缺口，见证据' if gaps else ''
    if gaps:
        return '待核实', brief(gaps), '查询不完整，不按符合统计'
    return '符合', success, ''


def parse_safe(text, account=True):
    rows = []
    for line in text.splitlines():
        f = line.split(':')
        if len(f) != (6 if account else 3) or not f[0] or any(ord(c)<32 for c in line):
            raise ValueError('安全字段输出格式异常')
        if not f[1].isdigit() or (account and (not f[2].isdigit() or f[5] not in ('shadowed','not-shadowed'))):
            raise ValueError('安全字段输出值异常')
        f[1] = int(f[1])
        if account:
            f[2] = int(f[2])
        rows.append(f)
    if not rows:
        raise ValueError('本地记录为空，不能判为符合')
    return rows


def account_checks(accounts, groups):
    out = {}
    if accounts is not None:
        out[21] = result([a[0]+'：非x标记' for a in accounts if a[5]!='shadowed'], [], '已查{}个账号，均为x标记'.format(len(accounts)))
    if accounts is not None and groups is not None:
        gids = {g[1] for g in groups}
        out[22] = result([a[0]+'：主GID='+str(a[2])+'不存在' for a in accounts if a[2] not in gids], [], '全部账号主GID均有本地组记录')
        shadow = [g for g in groups if g[0]=='shadow']
        bad = ['附加成员：'+g[2] for g in shadow if g[2]]
        bad += ['主组成员：'+a[0] for a in accounts if a[2] in {g[1] for g in shadow}]
        out[23] = result(bad, [] if len(shadow)==1 else ['shadow组记录缺失或重名，未推定为空'], 'shadow附加成员为空；无账号以其为主组')
    for i, rows, col, label in [(24,accounts,1,'UID'),(25,groups,1,'GID'),(26,accounts,0,'用户名'),(27,groups,0,'组名')]:
        if rows is None:
            continue
        buckets = collections.defaultdict(list)
        for row in rows:
            buckets[row[col]].append(row[0])
        bad = ['{}={}（{}条：{}）'.format(label,k,len(v),','.join(v)) for k,v in buckets.items() if len(v)>1]
        out[i] = result(bad, [], '已查{}条记录，未发现重复{}'.format(len(rows),label))
    for i in range(21,28):
        out.setdefault(i, ('待核实','所需本地账号/组记录未完整取得','读取错误见证据'))
    return out


def timeout_check(configs, gaps):
    declarations, unknown, valid = [], [], []
    for path, text in configs.items():
        values, readonly, exported = [], False, False
        complex_file = False
        for n, raw in enumerate(text.splitlines(),1):
            line = raw.split('#',1)[0].strip()
            if not re.search(r'\bTMOUT\b',line):
                continue
            origin = '{}:{}'.format(path,n)
            for part in line.split(';'):
                part = part.strip()
                if not part:
                    continue
                m = re.fullmatch(r'(?:(readonly|export)\s+|(?:typeset|declare)\s+(-[rx]+)\s+)?TMOUT=(?:[\x22\x27])?(\d+)(?:[\x22\x27])?',part)
                if m:
                    value = int(m[3]); values.append(value)
                    readonly |= m[1]=='readonly' or 'r' in (m[2] or '')
                    exported |= m[1]=='export' or 'x' in (m[2] or '')
                    declarations.append(origin+' TMOUT='+str(value))
                elif part=='readonly TMOUT':
                    readonly = True
                elif part=='export TMOUT':
                    exported = True
                else:
                    complex_file = True
                    unknown.append(origin+'：存在需人工解释的TMOUT表达式')
        if values and all(1<=v<=900 for v in values) and readonly and exported and not complex_file:
            valid.append(path)
        if values:
            declarations.append(path+' readonly='+str(readonly)+' export='+str(exported))
    evidence = declarations + unknown
    # 不执行Shell。条件、函数和外部source的效果不以字符串匹配伪装为运行值。
    if gaps or unknown:
        return ('待核实',brief(declarations) or '未取得完整TMOUT声明',brief(gaps+unknown)), evidence
    if not declarations:
        return ('不符合','所查全局Shell配置未设置TMOUT','配置检查；未启动新Shell'), evidence
    numbers = [int(m[1]) for d in declarations for m in [re.search(r'TMOUT=(\d+)$',d)] if m]
    if any(v<1 or v>900 for v in numbers) or not valid:
        return ('不符合',brief(declarations),'值越界或未同时配置readonly、export'), evidence
    return ('待核实',brief(declarations),'声明满足数值及属性要求；加载条件和各Shell覆盖需确认'), evidence


def umask_check(configs, other, gaps):
    declarations, unknown = [], []
    for path, text in dict(configs, **other).items():
        for n, raw in enumerate(text.splitlines(),1):
            line = raw.split('#',1)[0].strip()
            match = re.match(r'^(?:umask|UMASK)\s+(.+?)\s*$',line)
            if not match and 'pam_umask.so' in line:
                match = re.search(r'\bumask=([^\s]+)',line)
            if match:
                value = mask_number(match[1].strip())
                origin = '{}:{}'.format(path,n)
                if value is None:
                    unknown.append(origin+'：umask表达式需人工解释')
                else:
                    declarations.append((origin,value,path in configs))
            elif re.search(r'\b(?:umask|UMASK)\b',line) and 'pam_umask.so' not in line:
                unknown.append('{}:{}：非简单umask语句，未执行解释'.format(path,n))
    evidence = ['{} umask={:04o}'.format(p,v) for p,v,_ in declarations]+unknown
    private_groups = bool(re.search(r'^\s*USERGROUPS_ENAB\s+yes\b',other.get('/etc/login.defs',''),re.M))
    if private_groups:
        evidence.append('USERGROUPS_ENAB=yes：pam_umask对符合条件的私有组可能放宽组权限')
    shell = [d for d in declarations if d[2]]
    chosen = shell or declarations
    bad = ['{}={:04o}'.format(p,v) for p,v,_ in chosen if v & 0o027 != 0o027]
    if bad and chosen and all(v & 0o027 != 0o027 for _,v,_ in chosen) and not gaps and not unknown:
        return ('不符合',brief(bad),'发现宽于0027的配置；'+('另有读取/解析缺口' if gaps or unknown else '未作用户登录测试')), evidence
    if not declarations and not gaps and not unknown:
        return ('不符合','所查全局入口未见默认umask声明','未把当前root会话umask当成全局默认值'), evidence
    return ('待核实',brief(evidence) or '未完整取得默认umask配置','需确认加载优先级/PAM入口'+('及USERGROUPS_ENAB影响' if private_groups else '')+'；未直接验证用户会话'), evidence


def home_problem(account, meta):
    name, uid, gid, home = account[:4]
    bad = []
    if not stat.S_ISDIR(meta.st_mode):
        bad.append(name+'：家目录路径不是目录')
    if meta.st_uid != uid or stat.S_IMODE(meta.st_mode) & 0o027:
        bad.append('{} {}：UID={}，权限={:04o}'.format(name,home,meta.st_uid,stat.S_IMODE(meta.st_mode)))
    return bad


def dot_problem(account, path, meta):
    name, uid, gid = account[:3]
    base = posixpath.basename(path)
    mode = stat.S_IMODE(meta.st_mode)
    if base in ('.forward','.rhost'):
        return '{}：存在{}'.format(name,path), ''
    mask = 0o177 if base in ('.bash_history','.netrc') else 0o133
    if mode & mask or meta.st_uid != uid or meta.st_gid != gid:
        return '{}：{} UID={} GID={} 权限={:04o}'.format(name,path,meta.st_uid,meta.st_gid,mode), ''
    if base=='.netrc':
        return '', name+'：'+path+'权限合规，保留用途/本地策略待确认'
    return '', ''

def valid_shells(text):
    shells = set()
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        if not line.startswith('/') or len(line.split()) != 1:
            raise ValueError('/etc/shells存在未识别记录')
        if posixpath.basename(line) != 'nologin':
            shells.add(line)
    if not shells:
        raise ValueError('未取得有效Shell名单，不按空名单推定全部非交互')
    return shells


def mask_number(token):
    if re.fullmatch(r'[0-7]{3,4}', token):
        return int(token, 8) & 0o777
    pieces = token.split(',')
    if len(pieces) != 3:
        return None
    allowed, seen = 0, set()
    for part in pieces:
        m = re.fullmatch(r'([ugo])=([rwx]*)', part)
        if not m or m[1] in seen:
            return None
        seen.add(m[1])
        bits = sum(value for key, value in [('r', 4), ('w', 2), ('x', 1)] if key in m[2])
        allowed |= bits << {'u': 6, 'g': 3, 'o': 0}[m[1]]
    return 0o777 & ~allowed


def resolve_local_dir(path, check_mount, lstat_fn, readlink_fn):
    # Validate every prefix before following links; never resolve an unchecked remote path.
    if not path.startswith('/') or '..' in path.split('/'):
        raise ValueError('非绝对路径或含上级目录引用')
    parts, prefix, links = path.split('/')[1:], '/', 0
    while parts:
        part = parts.pop(0)
        if part in ('', '.'):
            continue
        current = posixpath.join(prefix, part)
        check_mount(current)
        st = lstat_fn(current)
        if stat.S_ISLNK(st.st_mode):
            links += 1
            if links > 40:
                raise OSError('符号链接层数过多或存在循环')
            target = readlink_fn(current)
            combined = target if target.startswith('/') else posixpath.join(prefix, target)
            # Link target is textual only here; its components are checked before access.
            parts = combined.split('/')[1:] + parts
            prefix = '/'
            if '..' in parts:
                raise ValueError('符号链接含上级目录引用，本批未跟随')
        else:
            if not stat.S_ISDIR(st.st_mode):
                raise NotADirectoryError(current + '不是目录')
            prefix = current
    check_mount(prefix)
    st = lstat_fn(prefix)
    if not stat.S_ISDIR(st.st_mode):
        raise NotADirectoryError(prefix + '不是目录')
    return prefix, st



def main():
    if sys.platform != 'linux':
        raise SystemExit('仅在目标Ubuntu运行；未执行任何采集。')
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['LC_ALL'] = 'C'
    os.umask(0o077)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    fd, proof_name = tempfile.mkstemp(prefix='G03_019_029_证据_' + stamp + '_', suffix='.txt', dir='.')
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
        log('范围及边界', 'G03-019～029；仅读全局策略、安全账号字段和文件元数据，不执行Shell配置；不执行sshd/-T/-t/ssh连接，不读取密钥、密码哈希及密码历史。', 0)
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


        if os.geteuid()!=0:
            raise OSError('请在已有root终端运行；本批不自动提权')
        assessed, configs, extra, gaps = {}, {}, {}, []
        paths = ['/etc/profile','/etc/bash.bashrc','/etc/bashrc']
        try:
            safe_file(Path('/etc/profile.d'), directory=True)
            names = sorted(Path('/etc/profile.d').iterdir())
            if len(names)>200:
                raise OSError('profile.d超过200项，未完整枚举')
            paths += [str(p) for p in names if p.name.endswith('.sh')]
        except OSError as exc:
            gaps.append(str(exc)); log('profile.d读取缺口',str(exc),1)
        for path in paths:
            try:
                configs[path] = read(path, optional=path=='/etc/bashrc')
            except OSError as exc:
                gaps.append(str(exc))
        assessed[19], evidence = timeout_check(configs,gaps)
        log('G03-019 白名单策略字段', '\n'.join(evidence) or '未匹配TMOUT声明',0 if not gaps else 1)
        mask_gaps = list(gaps)
        for path in ['/etc/login.defs','/etc/default/login','/etc/pam.d/common-session',
                     '/etc/pam.d/common-session-noninteractive','/etc/pam.d/login','/etc/pam.d/sshd','/etc/pam.d/postlogin']:
            try:
                extra[path] = read(path,optional=path in ('/etc/default/login','/etc/pam.d/postlogin','/etc/pam.d/sshd'))
            except OSError as exc:
                mask_gaps.append(str(exc))
        assessed[20], evidence = umask_check(configs,extra,mask_gaps)
        for path,text in extra.items():
            for number,line in enumerate(text.splitlines(),1):
                line=line.split('#',1)[0].strip()
                if 'pam_umask.so' in line:
                    evidence.append('{}:{} 存在pam_umask声明（不据此推定完整PAM调用链）'.format(path,number))
        log('G03-020 白名单策略字段','\n'.join(evidence) or '未匹配umask声明',0 if not mask_gaps else 1)

        accounts = groups = None
        for path, program, is_account in [('/etc/passwd',ACCOUNT_AWK,True),('/etc/group',GROUP_AWK,False)]:
            try:
                safe_file(Path(path))
                output, rc = run(['awk','-F:',program,path])
                if rc:
                    raise OSError('安全字段查询失败，退出码='+str(rc))
                rows = parse_safe(output,is_account)
                if is_account: accounts=rows
                else: groups=rows
            except (OSError,ValueError) as exc:
                log('本地账号数据缺口：'+path,str(exc),1)
        assessed.update(account_checks(accounts,groups))
        # 补充全部异常记录；简明结果只列前三条。
        if accounts is not None and groups is not None:
            for i in range(21,28):
                log('G03-{:03d} 对比结果'.format(i),' | '.join(assessed[i]),0)

        bad_home, gap_home, bad_dot, gap_dot, warnings = [], [], [], [], []
        homes_checked = dot_count = entries_count = 0
        try:
            if accounts is None:
                raise OSError('账号数据未完整取得')
            shells = valid_shells(read('/etc/shells'))
            targets = [a for a in accounts if a[4] in shells]
            log('家目录检查范围','\n'.join(a[0]+':'+a[3]+':'+a[4] for a in targets) or '无本地交互账号',0)
            mount_text, rc = run(['findmnt','-rn','--raw','-o','TARGET,FSTYPE'])
            if rc:
                raise OSError('本地挂载表查询失败；不遍历家目录')
            mounts = []
            for line in mount_text.splitlines():
                fields = line.split()
                if len(fields)!=2:
                    raise OSError('挂载表格式异常')
                path = re.sub(r'\\x([0-9a-fA-F]{2})',lambda m: chr(int(m[1],16)),fields[0])
                mounts.append((path,fields[1]))
            mounts.sort(key=lambda v:len(v[0]),reverse=True)
            if not any(p=='/' for p,_ in mounts):
                raise OSError('未取得根挂载点')

            def local_mount(path):
                for prefix, fs in mounts:
                    if path==prefix or path.startswith(prefix.rstrip('/')+'/'):
                        if fs not in ('ext2','ext3','ext4','xfs','btrfs','tmpfs','overlay','zfs'):
                            raise OSError('跳过非本地/未支持文件系统：'+path+' ('+fs+')')
                        return
                raise OSError('未找到挂载归属：'+path)

            start = time.monotonic()
            for account in targets:
                name,uid,gid,home = account[:4]
                home_ready = False
                try:
                    if home in ('','/','/etc','/usr','/var','/home','/tmp'):
                        raise ValueError('家目录范围过大或异常，未自动遍历：'+home)
                    resolved, meta = resolve_local_dir(home,local_mount,os.lstat,os.readlink)
                    if resolved in ('/','/etc','/usr','/var','/home','/tmp'):
                        raise ValueError('家目录解析后范围过大，未遍历：'+resolved)
                    homes_checked += 1
                    home_ready = True
                    problems = home_problem(account,meta)
                    bad_home += problems
                    log('家目录元数据', '{} {} -> {} UID={} GID={} 权限={:04o}'.format(name,home,resolved,meta.st_uid,meta.st_gid,stat.S_IMODE(meta.st_mode)),0)
                    stack = [resolved]
                    while stack:
                        folder = stack.pop()
                        if time.monotonic()-start>30 or entries_count>=50000:
                            raise TimeoutError('家目录遍历达到30秒/50000条上限；剩余范围未检查')
                        local_mount(folder)
                        # 用O_NOFOLLOW打开目录；不跟随扫描途中替换出的符号链接。
                        fd = os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                        try:
                            with os.scandir(fd) as iterator:
                                for entry in iterator:
                                    entries_count += 1
                                    if entries_count>50000 or time.monotonic()-start>30:
                                        raise TimeoutError('家目录遍历达到30秒/50000条上限；剩余范围未检查')
                                    child = posixpath.join(folder,entry.name)
                                    try:
                                        # 查挂载表在先；不stat自动挂载/远程挂载入口。
                                        local_mount(child)
                                        st = entry.stat(follow_symlinks=False)
                                        if st.st_dev != meta.st_dev:
                                            log('家目录跨文件系统边界',child+'：按原文-xdev不进入',0)
                                            continue
                                        if stat.S_ISDIR(st.st_mode):
                                            stack.append(child)
                                        elif stat.S_ISREG(st.st_mode) and entry.name.startswith('.'):
                                            dot_count += 1
                                            bad, warn = dot_problem(account,child,st)
                                            if bad: bad_dot.append(bad)
                                            if warn: warnings.append(warn)
                                            log('隐藏文件元数据','{} UID={} GID={} 权限={:04o}{}'.format(child,st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode),'；'+(bad or warn) if bad or warn else ''),0)
                                    except OSError as exc:
                                        gap_dot.append(str(exc)); log('隐藏文件查询缺口',str(exc),1)
                        finally:
                            os.close(fd)
                except FileNotFoundError as exc:
                    if not home_ready:
                        bad_home.append(name+'：家目录不存在 '+home)
                    else:
                        gap_dot.append(name+'：子路径不存在或采集中变化')
                    gap_dot.append(name+'：家目录或部分子路径未完成检查')
                    log('家目录缺失/变化',str(exc),1)
                except NotADirectoryError as exc:
                    if not home_ready:
                        bad_home.append(name+'：家目录路径不是目录 '+home)
                    gap_dot.append(name+'：非目录路径，未完成隐藏文件检查')
                    log('家目录类型异常',str(exc),1)
                except (OSError,ValueError) as exc:
                    # 目录已查、隐藏文件超时不撤销该目录已取得的权限证据。
                    if not home_ready:
                        gap_home.append(name+'：'+str(exc))
                    gap_dot.append(name+'：'+str(exc)); log('家目录覆盖缺口',name+'：'+str(exc),1)
            assessed[28] = result(bad_home,gap_home,'已查{}个交互账号家目录，存在/属主/权限均满足要求'.format(homes_checked))
            assessed[29] = result(bad_dot,gap_dot+warnings,'已查{}个家目录、{}个隐藏普通文件，所查元数据满足要求'.format(homes_checked,dot_count))
            for title, rows in [('家目录异常',bad_home+gap_home),('隐藏文件异常/限制',bad_dot+gap_dot+warnings)]:
                log(title,'\n'.join(rows) or '未发现',0 if not rows else 1)
            log('隐藏文件覆盖说明','递归、同一文件系统、不跟随符号链接；只取元数据；枚举{}项，检查{}个隐藏普通文件。原文禁止文件名为.forward/.rhost（单数）；.netrc存在须确认本地策略。'.format(entries_count,dot_count),0)
        except (OSError,ValueError) as exc:
            log('家目录检查无法完成',str(exc),1)
            assessed[28] = ('待核实',str(exc),'未取得完整家目录证据')
            assessed[29] = ('待核实',str(exc),'未取得完整隐藏文件证据')

        lines = ['G03-019～029｜全局用户环境、账号一致性及家目录',
                 '时间：'+datetime.now().astimezone().isoformat(timespec='seconds'),
                 '依据：CIS Ubuntu Linux 20.04 LTS v3.0.0 / Level 1 Server',
                 '019/020为静态配置核查；028/029只查元数据，不读取个人文件内容。']
        counts = {'符合':0,'不符合':0,'待核实':0}
        for index,name,cis,pages,rule in ITEMS:
            verdict,actual,why = assessed[index]
            counts['符合' if verdict.startswith('符合') else '不符合' if verdict.startswith('不符合') else '待核实'] += 1
            lines += ['', '[G03-{:03d}] {} | {}'.format(index,verdict,name),
                      '  基线：CIS {} / p.{}；推荐：{}'.format(cis,pages,rule),'  实际：'+actual]
            if why: lines.append('  说明：'+why)
        lines += ['', '本批统计：'+'；'.join(k+str(v)+'项' for k,v in counts.items()),
                  '本批共11项；第三组前批证据和待核实项仍需回填，不据此宣称整组完成。',
                  '详细证据：'+str(Path(proof_name).absolute())]
        fd, summary = tempfile.mkstemp(prefix='G03_019_029_结果_'+stamp+'_',suffix='.txt',dir='.')
        with os.fdopen(fd,'w',encoding='utf-8') as f: f.write('\n'.join(lines)+'\n')
        print('\n'.join(lines))
        print('\n简明结果：'+str(Path(summary).absolute()))
    except (OSError,UnicodeError,KeyboardInterrupt) as exc:
        log('停止；本批不完整',str(exc),1)
        print('已停止：{}\n保留证据：{}'.format(exc,Path(proof_name).absolute()),file=sys.stderr)
        return 2
    finally:
        proof.close()
    return 0

if __name__=='__main__': sys.exit(main())

G03_PY
