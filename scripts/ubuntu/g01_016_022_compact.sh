#!/usr/bin/env bash
# 仅在目标Ubuntu运行；无需安装软件、chmod或服务操作。
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  printf '%s\n' '请使用 bash g01_016_022_compact.sh 运行，不要source。' >&2
  return 2
fi
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' '停止：缺少python3；未执行采集，不安装软件。' >&2
  exit 127
fi
python3 - <<'PY_G01_016_022'
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
    (16, '每连接认证尝试次数', '5.1.16 / p.532–533', ['MaxAuthTries'], '不大于4'),
    (17, '单连接会话数量', '5.1.17 / p.534–535', ['MaxSessions'], '不大于10'),
    (18, '未认证连接并发控制', '5.1.18 / p.536–537', ['MaxStartups'], '10:30:60或更严格'),
    (19, '禁止空口令SSH认证', '5.1.19 / p.538–539', ['PermitEmptyPasswords'], 'no'),
    (20, '禁止root直接SSH登录', '5.1.20 / p.540–541', ['PermitRootLogin'], 'no'),
    (21, '禁止用户自定义SSH环境', '5.1.21 / p.542–543', ['PermitUserEnvironment'], 'no'),
    (22, 'SSH使用PAM', '5.1.22 / p.544–545', ['UsePAM'], 'yes'),
]
KEYS = {k.lower(): k for i in ITEMS for k in i[3]}

def documented_default(key, section):
    plain = re.sub(r'^\.(?:Cm|Dq|Qq|Sq|Em|Pa)\s+', '', section, flags=re.M)
    plain = re.sub(r'^\.[^\n]*', '', plain, flags=re.M)
    plain = ' '.join(plain.split()).replace('\\-', '-')
    m = re.search(r'\bThe default(?: value)? is\s+([A-Za-z0-9:-]+)(?=[\s.,;]|$)', plain)
    return m[1] if m else None

def assess(index, value):
    if value is None:
        return '待核实', '未取得可靠参数值；查看证据中的读取错误或声明冲突'
    if index in (16, 17):
        if not re.fullmatch(r'\d{1,9}', value):
            return '待核实', '参数不是本脚本支持的非负整数写法'
        limit = 4 if index == 16 else 10
        good = int(value) <= limit
        why = '所查值{}基线上限{}'.format('未超过' if good else '超过', limit)
        if value == '0':
            why += '；值为0对登录/会话可用性的影响须结合业务记录'
    elif index == 18:
        if value == '10:30:60':
            return '符合', '与基线推荐组合一致'
        m = re.fullmatch(r'(\d{1,9}):(\d{1,9}):(\d{1,9})', value)
        if not m:
            return '待核实', '非示例组合，需结合限制语义核对，不能只作数字大小比较'
        start, rate, full = map(int, m.groups())
        if not (0 < start <= full and 1 <= rate <= 100):
            return '待核实', '参数组合有效性需核对'
        if start > 10 or full > 60:
            return '不符合', '起始连接数超过10或全部拒绝连接数超过60'
        return '待核实', '非示例组合；原文审计表达式与丢弃概率方向需人工核对'
    elif index in (19, 22):
        if value not in ('yes', 'no'):
            return '待核实', '不是yes/no写法，未自动解释'
        good = value == ('yes' if index == 22 else 'no')
        why = '所查值' + ('满足' if good else '不满足') + '推荐要求'
    elif index == 20:
        if value not in ('yes', 'no', 'prohibit-password', 'without-password', 'forced-commands-only'):
            return '待核实', '未识别的root登录参数值'
        good = value == 'no'
        why = '禁止root直接SSH登录' if good else '所查值未完全禁止root直接SSH登录'
    else:
        good = value == 'no'
        why = '所查值' + ('满足' if good else '不满足') + '推荐要求'
    return ('符合' if good else '不符合'), why

def sections(text):
    result = {}
    matches = list(re.finditer(r'^\.It Cm ([A-Z][A-Za-z0-9]+)(?:[ \t].*)?$', text, re.M))
    for n, m in enumerate(matches):
        if m[1].lower() in KEYS:
            result[m[1].lower()] = text[m.end():matches[n+1].start() if n+1 < len(matches) else len(text)]
    return result


def main():
    if sys.platform != 'linux':
        raise SystemExit('仅在目标Ubuntu运行；未执行任何采集。')
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['LC_ALL'] = 'C'
    os.umask(0o077)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    fd, proof_name = tempfile.mkstemp(prefix='G01_016_022_证据_' + stamp + '_', suffix='.txt', dir='.')
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
        log('范围及边界', 'G01-016～022；仅读配置、手册和包版本；不执行sshd/-T/-t/ssh连接，不读取密钥。', 0)
        identity, rc = run(['uname', '-s', '-n', '-r', '-m'])
        if rc or identity != 'Linux lab-ubuntu20 5.4.0-216-generic x86_64':
            raise OSError('身份与已确认资产不一致，停止套用基线')
        distro, rc = run(['awk', '/^(ID|VERSION_ID)=/ {print}', '/etc/os-release'])
        if rc or not re.search(r'^ID="?ubuntu"?$', distro, re.M) or not re.search(r'^VERSION_ID="?20\.04"?$', distro, re.M):
            raise OSError('未确认Ubuntu 20.04')
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


        lines = ['G01-016～022｜SSH参数检查',
                 '时间：' + datetime.now().astimezone().isoformat(timespec='seconds'),
                 '口径：按已查配置声明及本机手册默认值对照；未直接验证运行中SSH生效值。',
                 '默认值仅在未见显式声明时使用；沿用上一批启动入口证据。']
        counts = {'符合': 0, '不符合': 0, '待核实': 0}
        for index, name, cis, keys, requirement in ITEMS:
            key = keys[0]
            decl = declarations[key.lower()]
            distinct = list(dict.fromkeys(v[0] for v in decl))
            if len(distinct) == 1:
                value = distinct[0]
                basis = '配置声明：' + '；'.join('{}:{}'.format(d[1], d[2]) for d in decl)
            elif len(distinct) > 1:
                value, basis = None, '多处不同声明：' + '；'.join('{}:{}={}'.format(d[1], d[2], d[0]) for d in decl)
            else:
                value, basis = defaults.get(key.lower()), '本机手册默认值；未显式配置'
            decision, why = assess(index, value)
            if gaps:
                why = '所取值对照：' + decision + '；存在读取或覆盖缺口，不能确定该项；' + why
                decision = '待核实'
            counts[decision] += 1
            lines += ['', '[G01-{:03d}] {} | {}'.format(index, decision, name),
                      '  基线：CIS ' + cis + '；推荐：' + requirement,
                      '  实际：{}={} [{}]'.format(key, value if value is not None else '未确定', basis),
                      '  说明：' + why]
        lines += ['', '本批对照统计：' + '；'.join('{} {}项'.format(k, v) for k, v in counts.items()),
                  '读取/覆盖缺口：' + ('；'.join(dict.fromkeys(gaps)) or '本批未发现'),
                  '仅本批7项；默认值对照不等同生效验证。结果回传后汇总第一组，不代表完成整份CIS基线。',
                  '详细证据：' + str(Path(proof_name).absolute())]
        fd, summary_name = tempfile.mkstemp(prefix='G01_016_022_结果_' + stamp + '_', suffix='.txt', dir='.')
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

PY_G01_016_022
