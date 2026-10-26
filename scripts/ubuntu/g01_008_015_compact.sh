#!/usr/bin/env bash
# 在目标Ubuntu中执行；只读配置、手册及包版本，保存本地TXT。
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  printf '%s\n' '请使用 bash g01_008_015_compact.sh 运行，不要source。' >&2
  return 2
fi
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' '停止：缺少python3，未安装软件、未执行采集。' >&2
  exit 127
fi
python3 - <<'PY_G01_008_015'
"""只读采集G01-008～015。默认值只从本机手册提取，不执行sshd。"""
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

ITEMS = [
    (8, '加密算法', '5.1.6 / p.508–510', ['Ciphers'], '排除原文弱算法；核对CVE-2023-48795补丁'),
    (9, '无响应连接处理', '5.1.7 / p.511–513', ['ClientAliveInterval', 'ClientAliveCountMax'], '两个值均大于0'),
    (10, '基于主机的认证', '5.1.10 / p.518–519', ['HostbasedAuthentication'], 'no'),
    (11, '忽略rhosts信任文件', '5.1.11 / p.520–521', ['IgnoreRhosts'], 'yes'),
    (12, '密钥交换算法', '5.1.12 / p.522–524', ['KexAlgorithms'], '排除group1-sha1、group14-sha1、group-exchange-sha1'),
    (13, '认证宽限时间', '5.1.13 / p.525–526', ['LoginGraceTime'], '1～60秒'),
    (14, '日志级别', '5.1.14 / p.527–528', ['LogLevel'], 'INFO或VERBOSE'),
    (15, '消息认证算法', '5.1.15 / p.529–531', ['MACs'], '排除原文弱MAC；核对CVE-2023-48795补丁'),
]
KEYS = {k.lower(): k for i in ITEMS for k in i[3]}
WEAK = {
    'ciphers': set('3des-cbc aes128-cbc aes192-cbc aes256-cbc blowfish-cbc cast128-cbc arcfour arcfour128 arcfour256 rijndael-cbc@lysator.liu.se'.split()),
    'kexalgorithms': set('diffie-hellman-group1-sha1 diffie-hellman-group14-sha1 diffie-hellman-group-exchange-sha1'.split()),
    'macs': set('hmac-md5 hmac-md5-96 hmac-ripemd160 hmac-sha1-96 umac-64@openssh.com hmac-md5-etm@openssh.com hmac-md5-96-etm@openssh.com hmac-ripemd160-etm@openssh.com hmac-sha1-96-etm@openssh.com umac-64-etm@openssh.com umac-128-etm@openssh.com'.split()),
}


def sections(text):
    result = {}
    matches = list(re.finditer(r'^\.It Cm ([A-Z][A-Za-z0-9]+)(?:[ \t].*)?$', text, re.M))
    for n, m in enumerate(matches):
        if m[1].lower() in KEYS:
            result[m[1].lower()] = text[m.end():matches[n+1].start() if n+1 < len(matches) else len(text)]
    return result


def documented_default(key, section):
    if key in WEAK:
        m = re.search(r'The default is:\s*\n\.Bd[^\n]*\n(.*?)\n\.Ed', section, re.S)
        if not m:
            return None
        value = re.sub(r'\s+', '', m[1]).replace('\\-', '-')
        return value if re.fullmatch(r'[a-zA-Z0-9@.,_-]+', value) else None
    plain = re.sub(r'^\.(?:Cm|Dq|Qq|Sq|Em|Pa)\s+', '', section, flags=re.M)
    plain = re.sub(r'^\.[^\n]*', '', plain, flags=re.M)
    plain = ' '.join(plain.split())
    m = re.search(r'\bThe default(?: value)? is\s+(no|yes|INFO|VERBOSE|[0-9]+)\b', plain)
    return m[1] if m else None


def assess(index, values, patched):
    if any(v is None for v in values):
        return '无法比较', '没有取得完整参数值；查看具体读取错误或默认值章节'
    if index in (8, 12, 15):
        key = {8: 'ciphers', 12: 'kexalgorithms', 15: 'macs'}[index]
        value = values[0]
        if value.startswith(('+', '-', '^')) or not re.fullmatch(r'[a-zA-Z0-9@.,_-]+', value):
            return '需解析', '包含算法增删、模式或复杂语法，未计算最终名单'
        algorithms = set(value.split(','))
        bad = sorted(algorithms & WEAK[key])
        if bad:
            return '不符合', '命中原文弱算法：' + ','.join(bad)
        if index in (8, 15) and patched is not True:
            if index == 15 or 'chacha20-poly1305@openssh.com' in algorithms:
                return '待核实', '未命中弱算法，但原文要求的补丁条件未确认'
        return '符合', '未命中原文弱算法' + ('；已安装包满足所查补丁版本条件' if index in (8, 15) and patched else '')
    if index == 9:
        interval = re.fullmatch(r'(\d{1,8})([smhdw]?)', values[0])
        count = re.fullmatch(r'\d{1,8}', values[1])
        if not interval or not count:
            return '需解析', '时间或次数使用了未支持的写法，需人工核对'
        good = int(interval[1]) > 0 and int(values[1]) > 0
    elif index == 13:
        m = re.fullmatch(r'(\d{1,8})([smhdw]?)', values[0])
        if not m:
            return '需解析', '认证时间的复合写法需人工核对'
        seconds = int(m[1]) * {'': 1, 's': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}[m[2]]
        good = 1 <= seconds <= 60
    elif index == 10:
        good = values[0] == 'no'
    elif index == 11:
        good = values[0] == 'yes'
    else:
        good = values[0] in ('INFO', 'VERBOSE')
    return ('符合', '所查值满足推荐要求') if good else ('不符合', '所查值不满足推荐要求')


def main():
    if sys.platform != 'linux':
        raise SystemExit('仅在目标Ubuntu运行；未执行任何采集。')
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['LC_ALL'] = 'C'
    os.umask(0o077)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    fd, proof_name = tempfile.mkstemp(prefix='G01_008_015_证据_' + stamp + '_', suffix='.txt', dir='.')
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
        log('范围及边界', 'G01-008～015；仅读配置、手册和包版本；不执行sshd/-T/-t/ssh连接，不读取密钥。', 0)
        identity, rc = run(['uname', '-s', '-n', '-r', '-m'])
        if rc or identity != 'Linux lab-ubuntu20 5.4.0-216-generic x86_64':
            raise OSError('身份与已确认资产不一致，停止套用基线')
        distro, rc = run(['awk', '/^(ID|VERSION_ID)=/ {print}', '/etc/os-release'])
        if rc or not re.search(r'^ID="?ubuntu"?$', distro, re.M) or not re.search(r'^VERSION_ID="?20\.04"?$', distro, re.M):
            raise OSError('未确认Ubuntu 20.04')
        package, pkg_rc = run(['dpkg-query', '-W', '-f=${Version}\t${db:Status-Abbrev}\n', 'openssh-server'])
        version = package.split('\t')[0] if pkg_rc == 0 else ''
        patched = None
        if pkg_rc == 0 and '\tii ' in package + ' ' and re.fullmatch(r'1:8\.2p1-4ubuntu0\.\d+(?:\+esm\d+)?', version):
            _, cmp_rc = run(['dpkg', '--compare-versions', version, 'ge', '1:8.2p1-4ubuntu0.10'])
            patched = True if cmp_rc == 0 else False if cmp_rc == 1 else None

        declarations = {k: [] for k in KEYS}
        gaps = []
        default_dir = Path('/etc/ssh/sshd_config.d')
        files = [Path('/etc/ssh/sshd_config')]
        try:
            safe_file(default_dir, directory=True)
            files += sorted(default_dir.glob('*.conf'))
        except OSError as exc:
            gaps.append(str(exc)); log('片段目录', str(exc), 1)
        if len(files) > 65:
            gaps.append('配置文件数量超过上限'); files = files[:65]
        includes = 0
        for path in files:
            try:
                safe_file(path)
                if path.stat().st_size > 1024 * 1024:
                    raise OSError('配置文件超过1MiB，停止读取')
                relevant = []
                for lineno, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
                    line = line.split('#', 1)[0].strip()
                    m = re.match(r'([A-Za-z]+)(?:\s*=\s*|\s+)(.*)', line)
                    if not m:
                        if line and line.split()[0].lower() in KEYS:
                            gaps.append('参数声明无法解析：' + str(path) + ':' + str(lineno))
                        continue
                    key, value = m[1].lower(), m[2].strip()
                    if key not in KEYS and key not in ('include', 'match'):
                        continue
                    relevant.append('{}:{}: {} {}'.format(path, lineno, key, value))
                    if key == 'include':
                        if str(path) == '/etc/ssh/sshd_config' and value == '/etc/ssh/sshd_config.d/*.conf':
                            includes += 1
                        else:
                            gaps.append('额外或复杂Include：' + str(path))
                    elif key == 'match':
                        gaps.append('存在Match条件：' + str(path))
                    else:
                        declarations[key].append((value, str(path), lineno))
                log('只读取本批必要声明：' + str(path), '\n'.join(relevant) or '未见本批显式声明', 0)
            except (OSError, UnicodeError) as exc:
                gaps.append(str(exc)); log('读取配置：' + str(path), str(exc), 1)
        if includes != 1:
            gaps.append('未确认唯一默认Include入口')

        manual = Path('/usr/share/man/man5/sshd_config.5.gz')
        defaults = {}
        try:
            safe_file(manual)
            with gzip.open(manual, 'rt', encoding='utf-8') as f:
                text = f.read(2 * 1024 * 1024 + 1)
            if len(text) > 2 * 1024 * 1024:
                raise OSError('手册展开后超过读取上限')
            owner, owner_rc = run(['dpkg-query', '-S', str(manual)])
            for key, section in sections(text).items():
                defaults[key] = documented_default(key, section)
                log('本机手册章节：' + KEYS[key], section.strip(), 0)
            if owner_rc or not owner.startswith('openssh-server:'):
                gaps.append('本机手册包归属未确认')
        except (OSError, UnicodeError, EOFError) as exc:
            gaps.append('手册读取失败'); log('本机手册', str(exc), 1)

        lines = ['G01-008～015｜SSH参数检查', '时间：' + datetime.now().astimezone().isoformat(timespec='seconds'),
                 'OpenSSH服务器包：' + (package or '未取得'),
                 'CVE-2023-48795包版本条件：' + ('满足' if patched is True else '不满足' if patched is False else '未确认'),
                 '注意：文档默认值是参考值，不冒充sshd生效输出；现有启动入口证据沿用上一批。']
        for index, name, cis, keys, requirement in ITEMS:
            values, bases, actual = [], [], []
            for key in keys:
                decl = declarations[key.lower()]
                distinct = list(dict.fromkeys(v[0] for v in decl))
                if len(distinct) == 1:
                    value, basis = distinct[0], '显式声明'
                elif len(distinct) > 1:
                    value, basis = None, '多处声明需核对顺序'
                else:
                    value, basis = defaults.get(key.lower()), '本机文档默认值（未显式配置）'
                values.append(value); bases.append(basis)
                actual.append('{}={} [{}]'.format(key, value if value is not None else '未确定', basis))
            decision, why = assess(index, values, patched)
            # 保留值级比较和依据层级，不把文档默认值升级为实测生效值。
            basis_label = '文档/声明对照，待复核' if any('文档' in b for b in bases) else '声明对照，待复核'
            if gaps:
                why = '已取得值的比较：' + decision + '；' + why
                decision = '待核实'
                basis_label += '；存在覆盖缺口'
            lines += ['', '[G01-{:03d}] {}（{}） | {}'.format(index, decision, basis_label, name),
                      '  基线：CIS ' + cis + '；推荐：' + requirement,
                      '  取证：' + '；'.join(actual), '  原因：' + why]
        lines += ['', '共有缺口：' + ('；'.join(dict.fromkeys(gaps)) or '未发现默认目录读取缺口；服务生效值仍未直接验证'),
                  '补丁依据：https://ubuntu.com/security/notices/USN-6560-1；仅核对指定CVE，不能推断全部补丁合规。',
                  '本批结束；结果回传后结合来源复核，不视为第一组已经完成。',
                  '详细证据：' + str(Path(proof_name).absolute())]
        fd, summary_name = tempfile.mkstemp(prefix='G01_008_015_结果_' + stamp + '_', suffix='.txt', dir='.')
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')
        print('\n'.join(lines))
        print('\n简明结果：' + str(Path(summary_name).absolute()))
    except (OSError, UnicodeError, KeyboardInterrupt) as exc:
        log('停止；本批不完整', str(exc) or '用户中断', 1)
        print('已停止：{}\n保留证据：{}'.format(exc, str(Path(proof_name).absolute())), file=sys.stderr)
        return 2
    finally:
        proof.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())

PY_G01_008_015
