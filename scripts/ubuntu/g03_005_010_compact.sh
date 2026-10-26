#!/usr/bin/env bash
# 仅在已确认的Ubuntu中运行；只读检查并保存本地TXT。
if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' '缺少python3，未执行检查；不自动安装。' >&2
  exit 127
fi
python3 - <<'G03_PY'
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





import posixpath
from pathlib import PurePosixPath

ITEMS = [
    (5, 'sudo安装', '5.2.1', '547–548', '安装sudo或sudo-ldap'),
    (6, 'sudo使用伪终端', '5.2.2', '549–550', '设置Defaults use_pty；不出现!use_pty'),
    (7, 'sudo独立日志配置', '5.2.3', '551–552', '配置Defaults logfile为日志文件路径'),
    (8, 'sudo重新认证', '5.2.5', '555–556', '不出现Defaults !authenticate'),
    (9, 'sudo认证缓存超时', '5.2.6', '557–558', 'timestamp_timeout为0～15分钟，结合本地策略'),
    (10, 'su访问限制', '5.2.7', '559–560', 'auth required/requisite pam_wheel.so use_uid group=空组'),
]
KEYS = ('use_pty', 'logfile', 'authenticate', 'timestamp_timeout')


def collect_sudo(read, list_directory, log):
    records, gaps, active, visited = [], [], set(), set()

    def walk(path, depth=0):
        path = PurePosixPath(posixpath.normpath(str(path)))
        if str(path) != '/etc/sudoers' and not str(path).startswith('/etc/sudoers.d/'):
            gaps.append('Include指向标准sudoers配置目录之外，本批不读取：' + str(path))
            return
        if depth > 16 or len(visited) >= 100 or path in active:
            gaps.append('sudoers引用深度、文件数量或循环异常：' + str(path))
            return
        active.add(path)
        visited.add(path)
        try:
            content = read(path)
            for n, raw in logical_lines(content):
                origin = '{}:{}'.format(path, n)
                match = re.match(r'^\s*([#@]include(?:dir)?)\s+(.+?)\s*$', raw)
                if match:
                    try:
                        values = shlex.split(match[2], comments=True)
                    except ValueError:
                        values = []
                    if len(values) != 1 or not re.fullmatch(r'[A-Za-z0-9_./-]+', values[0]):
                        gaps.append(origin + '：Include路径格式未覆盖')
                        continue
                    target = PurePosixPath(values[0])
                    if not target.is_absolute():
                        target = path.parent / target
                    target = PurePosixPath(posixpath.normpath(str(target)))
                    log('配置引用', origin + ' ' + match[1] + ' ' + str(target), 0)
                    if match[1].endswith('dir'):
                        if str(target) != '/etc/sudoers.d':
                            gaps.append(origin + '：非标准Include目录未读取')
                            continue
                        children = list_directory(target)
                        if len(children) > 100:
                            gaps.append(origin + '：Include目录超过100项')
                            continue
                        for name in sorted(children):
                            if '.' not in name and not name.endswith('~'):
                                walk(target / name, depth + 1)
                    else:
                        walk(target, depth + 1)
                    continue
                if re.match(r'^\s*[#@]include\b', raw) or raw.strip() in ('#includedir', '@includedir'):
                    gaps.append(origin + '：Include声明未完整解析')
                    continue
                rows, issues = parse_defaults(raw, origin)
                records.extend(rows)
                gaps.extend(issues)
                for row in rows:
                    log('sudoers白名单参数', '{} {}={}{}'.format(origin, row['key'], row['value'],
                        '（条件配置）' if row['scoped'] else ''), 0)
        except (OSError, UnicodeError, ValueError) as exc:
            gaps.append(str(path) + '：' + str(exc))
        finally:
            active.discard(path)

    walk(PurePosixPath('/etc/sudoers'))
    log('sudoers配置范围', '已涉及{}个配置文件；覆盖缺口{}项'.format(len(visited), len(gaps)), 0 if not gaps else 1)
    return records, gaps


def uncomment(line):
    quote = None
    escape = False
    for n, char in enumerate(line):
        if escape:
            escape = False
        elif char == '\\':
            escape = True
        elif quote:
            if char == quote:
                quote = None
        elif char in ('"', "'"):
            quote = char
        elif char == '#':
            return line[:n].strip()
    return line.strip()


def logical_lines(text):
    pending = ''
    start = 0
    for number, line in enumerate(text.splitlines(), 1):
        if not pending:
            start = number
        # Sudoers backslash-newline continuation, retaining the original first line.
        continued = (len(line) - len(line.rstrip('\\'))) % 2 == 1
        pending += line[:-1] + ' ' if continued else line
        if not continued:
            yield start, pending
            pending = ''
    if pending:
        raise ValueError('文件末尾存在未完成的续行')


def comma_parts(value):
    parts, part = [], ''
    quote, escaped = None, False
    for char in value:
        if escaped:
            part += char
            escaped = False
            continue
        if char == '\\':
            part += char
            escaped = True
            continue
        if quote:
            part += char
            if char == quote:
                quote = None
        elif char in ('"', "'"):
            quote = char
            part += char
        elif char == ',':
            parts.append(part.strip())
            part = ''
        else:
            part += char
    if quote or escaped:
        raise ValueError('Defaults引号或转义未闭合')
    parts.append(part.strip())
    return parts


def parse_defaults(raw, origin):
    """Return whitelisted declarations only; never emit command grants or arguments."""
    line = uncomment(raw)
    if not line.startswith('Defaults'):
        return [], []
    global_match = re.match(r'^Defaults\s+(.+)$', line)
    scoped = False
    if global_match:
        body = global_match[1]
    else:
        scoped_match = re.match(r'^Defaults[:>@!]\S+\s+(.+)$', line)
        if not scoped_match:
            return [], [origin + '：Defaults语法未完整解析']
        body, scoped = scoped_match[1], True
    records, errors = [], []
    try:
        parts = comma_parts(body)
    except ValueError as exc:
        return [], [origin + '：' + str(exc)]
    for part in parts:
        match = re.match(r'^(!?)([a-z_]+)(.*)$', part)
        if not match or match[2] not in KEYS:
            if re.search(r'\b(?:use_pty|logfile|authenticate|timestamp_timeout)\b', part):
                errors.append(origin + '：相关Defaults参数语法未完整解析')
            continue
        negative, key, rest = match.groups()
        value = None
        if key in ('use_pty', 'authenticate') and not rest.strip():
            value = not bool(negative)
        elif key == 'logfile' and negative and not rest.strip():
            value = False
        elif key == 'timestamp_timeout' and negative and not rest.strip():
            value = 0.0
        elif not negative:
            assignment = re.fullmatch(r'\s*=\s*(.*?)\s*', rest)
            if assignment:
                token = assignment[1]
                if len(token) >= 2 and token[0] == token[-1] and token[0] in ('"', "'"):
                    token = token[1:-1]
                if key == 'timestamp_timeout' and re.fullmatch(r'-?\d+(?:\.\d+)?', token):
                    value = float(token)
                elif key == 'logfile' and re.fullmatch(r'/[A-Za-z0-9_./-]+', token):
                    value = token
        if value is None:
            errors.append(origin + '：' + key + '值未按预期类型解析；未输出原值')
        else:
            records.append(dict(key=key, value=value, scoped=scoped, origin=origin))
    return records, errors


def manual_timeout(text):
    # Supports installed mdoc and man-format manuals without executing formatters.
    text = re.sub(r'\\f(?:\[[^]]+\]|\(..|[A-Za-z0-9])', '', text)
    text = text.replace('\\&', '').replace('\\-', '-')
    match = re.search(r'^\.(?:It|IP|B)\s+"?timestamp_timeout"?[^\n]*\n', text, re.M)
    if not match:
        return None
    tail = text[match.end():]
    stop = re.search(r'^\.(?:It|IP|TP|SH|SS)\b', tail, re.M)
    tail = tail[:stop.start()] if stop else tail[:4000]
    tail = re.sub(r'^\.[A-Za-z]+\s*', '', tail, flags=re.M)
    match = re.search(r'\bdefault\s+(?:value\s+)?is\s+(-?\d+(?:\.\d+)?)\b', tail, re.I)
    return float(match[1]) if match else None


def judge_defaults(index, records, gaps, inferred=None):
    key = {6: 'use_pty', 7: 'logfile', 8: 'authenticate', 9: 'timestamp_timeout'}[index]
    rows = [r for r in records if r['key'] == key]
    actual = '；'.join('{}={}{} [{}]'.format(key, str(r['value']).lower(),
                    '（条件配置）' if r['scoped'] else '', r['origin']) for r in rows)
    actual = actual or '所查配置未见' + key + '声明'
    # Missing coverage means even declarations may belong to a nonstandard policy.
    if gaps:
        return '待核实', actual, '配置来源/读取/语法存在缺口，见证据'
    if index in (6, 8):
        if any(r['value'] is False for r in rows):
            return '不符合', actual, '发现原文要求移除的!' + key
        if index == 8:
            return '符合', actual, '所查配置未出现!authenticate；不代表所有命令都要求密码'
        if any(r['value'] is True and not r['scoped'] for r in rows):
            return '符合', actual, '全局已声明use_pty，未发现禁用声明'
        if rows:
            return '待核实', actual, '仅有条件配置，未确认全局覆盖'
        return '不符合', actual, '未满足原文要求的Defaults use_pty显式配置'
    if any(r['scoped'] for r in rows):
        return '待核实', actual, '存在条件配置，需核对适用对象及覆盖顺序'
    if index == 7:
        if rows and isinstance(rows[-1]['value'], str):
            return '符合', actual, '按原文核对独立日志配置；未读取日志或验证写入'
        return '不符合', actual, '未配置有效的独立logfile路径'
    if rows:
        value = rows[-1]['value']
        return ('符合' if 0 <= value <= 15 else '不符合'), actual, '按配置值核对0～15分钟；本地另有更严要求时再核对'
    if inferred is None:
        return '待核实', actual, '未取得明确超时值，不凭记忆推定默认值'
    good = 0 <= inferred <= 15
    return ('符合（默认值推定）' if good else '不符合（默认值推定）'), \
        actual + '；本机已安装手册默认值={}分钟'.format(inferred), \
        '默认值推定，生效值未直接验证；本地另有更严要求时再核对'


def judge_su(text, group_text, passwd_text):
    found = []
    for n, raw in logical_lines(text):
        line = uncomment(raw)
        if not line or 'pam_wheel.so' not in line:
            continue
        fields = line.split()
        if len(fields) < 3 or fields[0] != 'auth' or fields[2] != 'pam_wheel.so':
            return '待核实', '发现非标准pam_wheel声明，行{}'.format(n), '需核对控制标志及模块路径'
        allowed = all(a == 'use_uid' or a == 'debug' or re.fullmatch(r'group=[A-Za-z_][A-Za-z0-9_-]*', a)
                      for a in fields[3:])
        names = [a[6:] for a in fields[3:] if a.startswith('group=')]
        if fields[1] not in ('required', 'requisite') or 'use_uid' not in fields[3:] or len(names) != 1:
            return '不符合', 'pam_wheel声明缺少本条必要控制标志/参数，行{}'.format(n), '要求required/requisite、use_uid和指定group'
        if not allowed:
            return '待核实', 'pam_wheel存在额外参数，行{}'.format(n), '需确认deny/trust/root_only等条件的影响'
        found.append((n, names[0]))
    if not found:
        return '不符合', '/etc/pam.d/su未见有效pam_wheel声明', '未满足本条规定的su入口配置；不推定其他认证机制'
    if len(found) != 1:
        return '待核实', '发现多条pam_wheel声明', '需核对顺序和交互关系'
    if group_text is None or passwd_text is None:
        return '待核实', 'pam_wheel已声明', '本地组或主组成员未能完整查询'
    line, name = found[0]
    entries = []
    for raw in group_text.splitlines():
        f = raw.split(':')
        if len(f) != 4 or not f[2].isdigit():
            return '待核实', '本地组记录结构异常', '不将异常或外部兼容记录当成空组'
        if f[0] == name:
            entries.append(f)
    if len(entries) != 1:
        return '待核实', 'group=' + name, '本地组缺失或重名；不查询外部账号源'
    group = entries[0]
    users = set(filter(None, group[3].split(',')))
    for raw in passwd_text.splitlines():
        f = raw.split(':')
        if len(f) != 7 or not f[2].isdigit() or not f[3].isdigit():
            return '待核实', '本地账号记录结构异常', '未完成主组成员核对'
        if int(f[3]) == int(group[2]):
            users.add(f[0])
    actual = '/etc/pam.d/su:{} pam_wheel use_uid group={}；本地成员={}'.format(
        line, name, ','.join(sorted(users)) or '无（含主组核对）')
    return ('不符合' if users else '符合'), actual, ('指定组不是空组' if users else '符合本地配置检查；未执行su测试')


def main():
    if sys.platform != 'linux':
        raise SystemExit('仅在目标Ubuntu运行；未执行任何采集。')
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['LC_ALL'] = 'C'
    os.umask(0o077)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    fd, proof_name = tempfile.mkstemp(prefix='G03_005_010_证据_' + stamp + '_', suffix='.txt', dir='.')
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
        log('范围及边界', 'G03-005～010；仅读sudo/su配置、包状态及必要本地账号组字段，不执行sudo/su或认证测试；不执行sshd/-T/-t/ssh连接，不读取密钥、密码哈希及密码历史。', 0)
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

        def list_directory(path):
            path = Path(path)
            safe_file(path, directory=True)
            return [p.name for p in path.iterdir()]

        # Query packages separately: absence is only inferred from the explicit dpkg diagnostic.
        packages, package_errors = [], []
        for package in ('sudo', 'sudo-ldap'):
            output, rc = run(['dpkg-query', '-W', '-f=${Status}\t${Version}\n', package])
            if rc == 0:
                fields = output.split('\t')
                if len(fields) == 2 and fields[0] == 'install ok installed':
                    packages.append(package + '=' + fields[1])
                elif len(fields) != 2 or not re.fullmatch(r'\S+ \S+ \S+', fields[0]):
                    package_errors.append(package + '状态输出异常')
            elif rc == 1 and 'no packages found matching ' + package in output:
                pass
            else:
                package_errors.append(package + '查询失败/工具缺失')
        assessed = {5: ('符合', '；'.join(packages), '已安装所需软件包') if packages else
                   ('待核实', '；'.join(package_errors), '不能把查询失败当成未安装') if package_errors else
                   ('不符合', 'sudo、sudo-ldap均未处于已安装状态', '未满足指定软件包安装要求')}

        source_gaps = []
        nss = None
        try:
            sudo_conf = read('/etc/sudo.conf', optional=True)
            policy_rows = []
            for n, raw in logical_lines(sudo_conf):
                line = uncomment(raw)
                if not line.startswith('Plugin'):
                    continue
                fields = line.split()
                if len(fields) != 3 or fields[1] not in ('sudoers_policy', 'sudoers_io') or fields[2] != 'sudoers.so':
                    source_gaps.append('/etc/sudo.conf:{}存在非标准插件或插件参数；未输出参数原文'.format(n))
                if len(fields) > 1 and fields[1] == 'sudoers_policy':
                    policy_rows.append(n)
            if len(policy_rows) > 1:
                source_gaps.append('存在多条sudoers_policy插件声明')
        except (OSError, ValueError) as exc:
            source_gaps.append(str(exc))
        try:
            nss = read('/etc/nsswitch.conf')
            nss_sudo = []
            for raw in nss.splitlines():
                line = uncomment(raw)
                if re.match(r'^sudoers\s*:', line):
                    nss_sudo.append(line.split(':', 1)[1].strip())
            if len(nss_sudo) > 1 or (nss_sudo and nss_sudo[0] != 'files'):
                source_gaps.append('sudoers来源不是单一本地files，未查询其他来源')
            log('sudoers来源', '未声明sudoers来源，按标准本地入口检查' if not nss_sudo else
                '本地files' if nss_sudo == ['files'] else '非单一本地来源；未连接其他资产', 0)
        except OSError as exc:
            source_gaps.append(str(exc))
        records, gaps = collect_sudo(read, list_directory, log)
        gaps = source_gaps + gaps
        if not packages:
            gaps.append('未确认安装sudo/sudo-ldap，配置不能判为完整符合')
        for issue in gaps:
            log('配置缺口', issue, 1)

        inferred = None
        if packages and not gaps and not any(r['key'] == 'timestamp_timeout' for r in records):
            try:
                manual = read('/usr/share/man/man5/sudoers.5.gz', compressed=True)
                inferred = manual_timeout(manual)
                log('本机sudoers手册默认超时', '未能提取明确数值' if inferred is None else
                    'timestamp_timeout默认值={}分钟；这是手册推定值'.format(inferred), 1 if inferred is None else 0)
            except OSError:
                pass
        for index in (6, 7, 8, 9):
            assessed[index] = judge_defaults(index, records, gaps, inferred)

        try:
            su = read('/etc/pam.d/su')
            group_data = passwd_data = None
            # Only query group membership when a pam_wheel declaration actually needs it.
            if any('pam_wheel.so' in uncomment(line) for line in su.splitlines()):
                try:
                    group_data = read('/etc/group')
                    passwd_data = read('/etc/passwd')
                except OSError:
                    pass
            assessed[10] = judge_su(su, group_data, passwd_data)
            if assessed[10][0] == '符合':
                local_only = nss is not None
                for key in ('passwd', 'group'):
                    entries = [uncomment(line).split(':', 1)[1].split()
                               for line in (nss or '').splitlines()
                               if re.match(r'^' + key + r'\s*:', uncomment(line))]
                    if len(entries) != 1 or not entries[0] or entries[0][0] != 'files' or set(entries[0]) - {'files', 'systemd'}:
                        local_only = False
                if not local_only:
                    assessed[10] = ('待核实', assessed[10][1], '本地组为空，但账号/组来源覆盖未确认；未查询外部来源')
            log('su白名单配置及组核对', assessed[10][1] + '\n' + assessed[10][2], 0)
        except (OSError, ValueError) as exc:
            assessed[10] = ('待核实', '/etc/pam.d/su或账号组数据未完整取得', str(exc))
            log('su检查失败', str(exc), 1)

        lines = ['G03-005～010｜sudo/su配置',
                 '时间：' + datetime.now().astimezone().isoformat(timespec='seconds'),
                 '依据：CIS Ubuntu 20.04 LTS v3.0.0 / Level 1 Server',
                 '口径：本地配置检查；不执行sudo/su，不读取日志正文，不测试认证。']
        counts = {'符合': 0, '不符合': 0, '待核实': 0}
        for index, name, cis, pages, rule in ITEMS:
            verdict, actual, why = assessed[index]
            counts['符合' if verdict.startswith('符合') else '不符合' if verdict.startswith('不符合') else '待核实'] += 1
            lines += ['', '[G03-{:03d}] {} | {}'.format(index, verdict, name),
                      '  基线：CIS {} / p.{}；推荐：{}'.format(cis, pages, rule),
                      '  实际：' + actual]
            if why:
                lines += ['  说明：' + why]
        lines += ['', '本批统计：' + '；'.join(k + str(v) + '项' for k, v in counts.items()),
                  '仅本批6项；G03共29项。G03-001的本地策略仍待确认。',
                  '详细证据：' + str(Path(proof_name).absolute())]
        fd, summary = tempfile.mkstemp(prefix='G03_005_010_结果_' + stamp + '_', suffix='.txt', dir='.')
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')
        print('\n'.join(lines))
        print('\n简明结果：' + str(Path(summary).absolute()))
    except (OSError,UnicodeError,KeyboardInterrupt) as exc:
        log('停止；本批不完整',str(exc),1)
        print('已停止：{}\n保留证据：{}'.format(exc,Path(proof_name).absolute()),file=sys.stderr)
        return 2
    finally:
        proof.close()
    return 0

if __name__=='__main__': sys.exit(main())

G03_PY
