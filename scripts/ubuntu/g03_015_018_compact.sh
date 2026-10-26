#!/usr/bin/env bash
# 在既有root终端运行；不执行sudo/su或加载新的Shell配置。
if [[ ! -x /usr/bin/python3 ]]; then
  printf '%s\n' '缺少可执行的/usr/bin/python3，未执行检查；不自动安装。' >&2
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





import time
import posixpath

ITEMS = [
    (15, 'root PATH安全', '5.4.2.5', '667–669', '无空项、当前目录或无效目录；目录属主root，组和其他用户不可写'),
    (16, 'root umask', '5.4.2.6', '670–671', 'umask为0027或更严格；新目录不宽于0750，新文件不宽于0640'),
    (17, '系统账号登录Shell', '5.4.2.7', '672–673', '适用系统账号不得使用有效登录Shell，保留原文例外'),
    (18, '非交互账号密码锁定', '5.4.2.8', '674–675', '除root外，没有有效登录Shell的账号密码状态应为L'),
]
PASSWD_SHELL_AWK = r'''BEGIN {bad=0}
NF != 7 || $1 == "" || $3 !~ /^[0-9]+$/ {bad++; next}
{print $1 ":" $3 ":" $7}
END {if (bad) {print "ERROR: malformed/compat passwd records=" bad; exit 2}}
'''


def parse_accounts(text):
    result, names = [], set()
    for line in text.splitlines():
        fields = line.split(':')
        if len(fields) != 3 or not fields[0] or not re.fullmatch(r'\d+', fields[1]):
            raise ValueError('账号/Shell输出结构异常')
        if fields[0] in names or any(ord(c) < 32 for c in fields[0] + fields[2]):
            raise ValueError('账号重名或存在控制字符')
        names.add(fields[0])
        result.append((fields[0], int(fields[1]), fields[2]))
    if not result:
        raise ValueError('账号记录为空')
    return result


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


def uid_minimum(text):
    values = []
    for raw in text.splitlines():
        line = raw.split('#', 1)[0].strip()
        if re.match(r'^UID_MIN\b', line):
            match = re.fullmatch(r'UID_MIN\s+(\d+)', line)
            if not match:
                raise ValueError('UID_MIN参数格式异常')
            values.append(int(match[1]))
    if len(set(values)) != 1 or not values or values[0] <= 0:
        raise ValueError('UID_MIN缺失或冲突，不推定1000')
    return values[0]


def system_shell_result(accounts, shells, minimum):
    exceptions = {'root', 'halt', 'sync', 'shutdown', 'nfsnobody'}
    targets = [a for a in accounts if a[0] not in exceptions and (a[1] < minimum or a[1] == 65534)]
    bad = [a for a in targets if a[2] in shells]
    actual = 'UID_MIN={}；已查{}个适用系统账号'.format(minimum, len(targets))
    if bad:
        actual += '；有效Shell：' + '；'.join('{}(UID={})={}'.format(*a) for a in bad)
    else:
        actual += '；未发现使用有效登录Shell的账号'
    return ('不符合' if bad else '符合'), actual, '按/etc/shells和原文例外判断；未测试登录'


def lock_result(targets, states, failures):
    bad = [(name, states[name]) for name in targets if name in states and states[name] != 'L']
    missing = [name for name in targets if name not in states]
    if bad:
        return '不符合', '未锁定：' + '；'.join(n + '=' + s for n, s in bad), \
            '另有查询缺口，见证据' if missing or failures else '没有有效登录Shell，仍应锁定密码'
    if missing or failures:
        return '待核实', '已取得{}个状态；未完成{}个'.format(len(states), len(missing)), '存在查询限制或错误，不能推定全部锁定'
    return '符合', '已查{}个非root、无有效登录Shell账号，密码状态均为L'.format(len(targets)), \
        'L表示密码锁定，不等于禁止全部认证方式'


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


def mask_declarations(text, source, login_defs=False):
    result, unknown = [], []
    keyword = 'UMASK' if login_defs else 'umask'
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split('#', 1)[0].strip()
        if not line or not re.match(r'^' + keyword + r'\b', line):
            continue
        fields = line.split()
        value = mask_number(fields[1]) if len(fields) == 2 else None
        origin = '{}:{}'.format(source, n)
        if value is None:
            unknown.append(origin + '：umask为表达式或非简单声明，未执行解析')
        else:
            result.append((value, origin))
    return result, unknown


def mask_result(current, declarations, gaps):
    weak = [(value, origin) for value, origin in declarations if value & 0o027 != 0o027]
    actual = '继承的root会话umask未取得' if current is None else \
        '继承的root会话umask={:04o}；新目录上限={:04o}，新文件上限={:04o}'.format(
            current, 0o777 & ~current, 0o666 & ~current)
    if weak:
        actual += '；宽松声明：' + '；'.join('{}={:04o}'.format(origin, value) for value, origin in weak)
    if current is not None and current & 0o027 != 0o027:
        return '不符合（当前root会话）', actual, '当前掩码未满足0027；文件上限按位计算，未创建测试文件'
    if gaps or weak or current is None:
        return '待核实', actual, '存在读取/解析缺口或声明与当前值不一致；需核对配置覆盖关系'
    return '符合（当前会话及所查声明）', actual, '未启动新登录Shell；不能据此证明所有登录入口'


def local_nss(text):
    for key in ('passwd', 'shadow', 'group'):
        rows = [line.split('#', 1)[0].split(':', 1)[1].strip().split()
                for line in text.splitlines() if re.match(r'^\s*' + key + r'\s*:', line)]
        if len(rows) != 1 or not rows[0] or rows[0][0] != 'files' or set(rows[0]) - {'files', 'systemd'}:
            return False
    return True


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


def path_result(value, query):
    bad, gaps, count = [], [], 0
    entries = value.split(':')
    if len(entries) > 100:
        return '待核实', 'PATH超过100项', '本批未展开全部路径'
    for entry in dict.fromkeys(entries):
        if not entry or entry == '.' or not entry.startswith('/'):
            bad.append('空项/当前目录' if not entry or entry == '.' else '相对路径：' + entry)
            continue
        try:
            real, st = query(entry)
            count += 1
            if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
                bad.append('{} UID={} 权限={:04o}'.format(entry, st.st_uid, stat.S_IMODE(st.st_mode)))
        except (FileNotFoundError, NotADirectoryError):
            bad.append(entry + '不存在或不是目录')
        except (OSError, ValueError) as exc:
            gaps.append(entry + '：' + str(exc))
    if bad:
        return '不符合（当前root会话）', '；'.join(bad), '另有未完成路径，见证据' if gaps else '检查的是调用本脚本时继承的PATH'
    if gaps:
        return '待核实', '；'.join(gaps), '路径读取有缺口，不能按全部符合判定'
    return '符合（当前root会话）', '已查{}个目录；属主均为root，组/其他用户不可写；无空项或当前目录'.format(count), \
        '未执行sudo -i或加载登录脚本，未验证新登录Shell的PATH'


def main():
    if sys.platform != 'linux':
        raise SystemExit('仅在目标Ubuntu运行；未执行任何采集。')
    original_path = os.environ.get('PATH', '')
    original_umask = None
    try:
        with open('/proc/self/status', encoding='ascii') as inherited:
            for line in inherited:
                match = re.fullmatch(r'Umask:\s+([0-7]{3,4})\s*', line)
                if match:
                    original_umask = int(match[1], 8)
                    break
    except (OSError, UnicodeError):
        pass
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['LC_ALL'] = 'C'
    os.umask(0o077)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    fd, proof_name = tempfile.mkstemp(prefix='G03_015_018_证据_' + stamp + '_', suffix='.txt', dir='.')
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
        log('范围及边界', 'G03-015～018；检查当前root环境及本地账号Shell；用passwd -S查询状态，不执行登录测试；不执行sshd/-T/-t/ssh连接，不直接读取shadow、密钥或密码历史；状态工具仅输出账号状态。', 0)
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


        if os.geteuid() != 0:
            raise OSError('本批要求在现有root终端运行；不自动提权')
        log('采集前继承的环境', 'PATH=' + original_path + '\numask=' +
            ('未取得' if original_umask is None else '{:04o}'.format(original_umask)),
            1 if original_umask is None else 0)

        mount_cache = {}

        def local_mount(path):
            if path in mount_cache:
                return
            fs, rc = run(['findmnt', '-rn', '--nocanonicalize', '-T', path, '-o', 'FSTYPE'])
            if rc or fs not in ('ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'tmpfs', 'overlay', 'zfs'):
                raise OSError('未确认本地挂载，未访问该路径')
            mount_cache[path] = fs

        def query_directory(path):
            try:
                resolved, metadata = resolve_local_dir(path, local_mount, os.lstat, os.readlink)
                log('PATH目录元数据', '{} -> {}；UID={}；权限={:04o}'.format(
                    path, resolved, metadata.st_uid, stat.S_IMODE(metadata.st_mode)), 0)
                return resolved, metadata
            except (OSError, ValueError) as exc:
                log('PATH目录查询失败', path + '：' + str(exc), 1)
                raise

        assessed = {15: path_result(original_path, query_directory)}
        declarations, mask_gaps = [], []
        login_defs = None
        for filename in ('/root/.bash_profile', '/root/.bash_login', '/root/.profile', '/root/.bashrc', '/etc/login.defs'):
            try:
                content = read(filename, optional=filename.startswith('/root/'))
                if filename == '/etc/login.defs':
                    login_defs = content
                values, errors = mask_declarations(content, filename, filename == '/etc/login.defs')
                declarations.extend(values)
                mask_gaps.extend(errors)
                for value, source in values:
                    log('umask显式声明', source + ' umask={:04o}'.format(value), 0)
                if not values and not errors:
                    log('umask声明检查', filename + '未见单独一行的简单umask声明', 0)
            except OSError as exc:
                mask_gaps.append(str(exc))
        for error in mask_gaps:
            log('umask解析/读取缺口', error, 1)
        assessed[16] = mask_result(original_umask, declarations, mask_gaps)

        accounts = shells = None
        try:
            safe_file(Path('/etc/passwd'))
            output, rc = run(['awk', '-F:', PASSWD_SHELL_AWK, '/etc/passwd'])
            if rc:
                raise OSError('账号名/UID/Shell查询失败；退出码=' + str(rc))
            accounts = parse_accounts(output)
            shells = valid_shells(read('/etc/shells'))
            log('有效登录Shell名单', '\n'.join(sorted(shells)), 0)
            if login_defs is None:
                raise OSError('/etc/login.defs未能读取')
            minimum = uid_minimum(login_defs)
            log('系统账号UID阈值', 'UID_MIN=' + str(minimum), 0)
            assessed[17] = system_shell_result(accounts, shells, minimum)
        except (OSError, ValueError) as exc:
            log('系统账号Shell检查缺口', str(exc), 1)
            assessed[17] = ('待核实', '账号/Shell名单或UID_MIN未完整取得', str(exc))

        if accounts is None or shells is None:
            assessed[18] = ('待核实', '账号或有效Shell名单未取得', '不能确定需要查询锁定状态的账号范围')
        else:
            targets = [a[0] for a in accounts if a[0] != 'root' and a[2] not in shells]
            statuses, failures = {}, []
            try:
                if targets and not local_nss(read('/etc/nsswitch.conf')):
                    raise OSError('账号/组/影子记录来源不满足本地查询前提；未调用passwd')
                started = time.monotonic()
                for name in targets:
                    if len(statuses) >= 200 or time.monotonic() - started > 30:
                        failures.append('超过本批账号数/时间上限，剩余账号未查询')
                        break
                    output, rc = run(['passwd', '-S', '--', name])
                    fields = output.split()
                    if rc != 0 or len(fields) != 7 or fields[0] != name or fields[1] not in ('P', 'L', 'NP'):
                        failures.append(name + '状态查询失败或格式异常')
                        if rc in (126, 127):
                            break
                    else:
                        statuses[name] = fields[1]
                assessed[18] = lock_result(targets, statuses, failures)
            except OSError as exc:
                failures.append(str(exc))
                assessed[18] = lock_result(targets, statuses, failures)
            for failure in failures:
                log('账号状态查询缺口', failure, 1)

        lines = ['G03-015～018｜root环境与系统账号',
                 '时间：' + datetime.now().astimezone().isoformat(timespec='seconds'),
                 '依据：CIS Ubuntu 20.04 LTS v3.0.0 / Level 1 Server',
                 '015/016明确限定当前root会话及所查声明；不启动新登录Shell、不创建测试文件。']
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
                  '本批仅4项，不代表G03全部29项完成。',
                  '详细证据：' + str(Path(proof_name).absolute())]
        fd, summary = tempfile.mkstemp(prefix='G03_015_018_结果_' + stamp + '_', suffix='.txt', dir='.')
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
