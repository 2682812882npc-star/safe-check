#!/usr/bin/env bash
# 当前批次只读采集本地账号编号；root密码状态复用已有证据。
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






ITEMS = [
    (11, '唯一UID 0账号', '5.4.2.1', '659–660', '只有root的UID为0'),
    (12, 'GID 0账号限制', '5.4.2.2', '661–662', 'root主组GID为0；除sync/shutdown/halt/operator外无其他GID 0账号'),
    (13, '唯一GID 0组', '5.4.2.3', '663–664', '只有root组的GID为0'),
    (14, 'root密码状态', '5.4.2.4', '665–666', 'root密码状态为P或L，不得为NP'),
]

PASSWD_AWK = r"""BEGIN {bad=0}
NF != 7 || $1 == "" || $3 !~ /^[0-9]+$/ || $4 !~ /^[0-9]+$/ {bad++; next}
$1 == "root" || $3 == 0 || $4 == 0 {print $1 ":" $3 ":" $4}
END {if (bad) {print "ERROR: malformed/compat passwd records=" bad; exit 2}}
"""
GROUP_AWK = r"""BEGIN {bad=0}
NF != 4 || $1 == "" || $3 !~ /^[0-9]+$/ {bad++; next}
$1 == "root" || $3 == 0 {print $1 ":" $3}
END {if (bad) {print "ERROR: malformed/compat group records=" bad; exit 2}}
"""


def parse_selected(text, width):
    rows = []
    for line in text.splitlines():
        fields = line.split(':')
        if len(fields) != width or not fields[0] or not all(re.fullmatch(r'[0-9]+', f) for f in fields[1:]):
            raise ValueError('账号编号查询输出格式异常')
        rows.append((fields[0],) + tuple(int(f) for f in fields[1:]))
    return rows


def assess_ids(index, rows):
    if rows is None:
        return '待核实', '未完整取得本地账号/组字段', '读取或命令失败，不能按无异常判定'
    root = [r for r in rows if r[0] == 'root']
    if index == 11:
        zero = [r for r in rows if r[1] == 0]
        good = len(root) == 1 and root[0][1] == 0 and len(zero) == 1 and zero[0][0] == 'root'
        actual = 'UID=0账号：' + ('、'.join(r[0] for r in zero) or '无')
    elif index == 12:
        exceptions = {'sync', 'shutdown', 'halt', 'operator'}
        zero = [r for r in rows if r[2] == 0 and r[0] not in exceptions]
        excluded = [r[0] for r in rows if r[2] == 0 and r[0] in exceptions]
        good = len(root) == 1 and root[0][2] == 0 and len(zero) == 1 and zero[0][0] == 'root'
        actual = '主组GID=0账号：' + ('、'.join(r[0] for r in zero) or '无')
        if excluded:
            actual += '；原文允许的例外：' + '、'.join(excluded)
    else:
        zero = [r for r in rows if r[1] == 0]
        good = len(root) == 1 and root[0][1] == 0 and len(zero) == 1 and zero[0][0] == 'root'
        actual = 'GID=0组：' + ('、'.join(r[0] for r in zero) or '无')
    if len(root) != 1:
        actual += '；root记录数量=' + str(len(root))
    elif (root[0][2] if index == 12 else root[0][1]) != 0:
        actual += '；root对应编号不是0'
    return ('符合' if good else '不符合'), actual, '仅核对本地账号数据库；不查询外部身份源'

def main():
    if sys.platform != 'linux':
        raise SystemExit('仅在目标Ubuntu运行；未执行任何采集。')
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['LC_ALL'] = 'C'
    os.umask(0o077)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    fd, proof_name = tempfile.mkstemp(prefix='G03_011_014_证据_' + stamp + '_', suffix='.txt', dir='.')
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
        log('范围及边界', 'G03-011～014；仅读本地账号名、UID和GID；014复用已提供的G02账号状态证据；不执行sshd/-T/-t/ssh连接，不读取密钥、密码哈希及密码历史。', 0)
        identity, rc = run(['uname', '-s', '-n', '-r', '-m'])
        if rc or identity != 'Linux lab-ubuntu20 5.4.0-216-generic x86_64':
            raise OSError('身份与已确认资产不一致，停止套用基线')
        distro, rc = run(['awk', '/^(ID|VERSION_ID)=/ {print}', '/etc/os-release'])
        if rc or not re.search(r'^ID="?ubuntu"?$', distro, re.M) or not re.search(r'^VERSION_ID="?20\.04"?$', distro, re.M):
            raise OSError('未确认Ubuntu 20.04')




        data = {}
        for name, path, program, width in [
            ('passwd', '/etc/passwd', PASSWD_AWK, 3),
            ('group', '/etc/group', GROUP_AWK, 2),
        ]:
            try:
                safe_file(Path(path))
                output, rc = run(['awk', '-F:', program, path])
                if rc != 0:
                    raise OSError(path + '查询失败；退出码=' + str(rc))
                data[name] = parse_selected(output, width)
            except (OSError, ValueError) as exc:
                data[name] = None
                log('账号编号取证缺口', str(exc), 1)
        assessed = {index: assess_ids(index, data['group' if index == 13 else 'passwd'])
                    for index in (11, 12, 13)}
        assessed[14] = ('符合（复用已有证据）', 'G02人工补查截图：root状态=P；取证日期2026-10-08',
                        '沿用同一资产已提供证据，本次未重新查询；P表示已设置密码，不代表禁止root通过SSH登录')
        log('G03-014已有证据引用',
            '来源：用户回传G02账号状态截图codex-clipboard-e52674cb-a294-4d95-9361-5f7127b03375.png\n'
            '原查询：LC_ALL=C passwd -S -a；原退出码：0\n'
            '相关字段：root P；原证据当前日期：2026-10-08 UTC\n'
            '这是历史证据引用，不是本轮新执行命令。', 0)
        lines = ['G03-011～014｜特权账号编号与root密码状态',
                 '本轮时间：' + datetime.now().astimezone().isoformat(timespec='seconds'),
                 '依据：CIS Ubuntu 20.04 LTS v3.0.0 / Level 1 Server',
                 '011～013为本轮只读采集；014引用2026-10-08已提供证据，未重新查询。']
        counts = {'符合': 0, '不符合': 0, '待核实': 0}
        for index, name, cis, pages, rule in ITEMS:
            verdict, actual, why = assessed[index]
            counts['符合' if verdict.startswith('符合') else verdict] += 1
            lines += ['', '[G03-{:03d}] {} | {}'.format(index, verdict, name),
                      '  基线：CIS {} / p.{}；推荐：{}'.format(cis, pages, rule),
                      '  实际：' + actual]
            if why:
                lines += ['  说明：' + why]
        lines += ['', '本批统计：' + '；'.join(k + str(v) + '项' for k, v in counts.items()),
                  '本批4项，其中1项复用旧证据；不代表G03全部29项已完成。',
                  '详细证据：' + str(Path(proof_name).absolute())]
        fd, summary = tempfile.mkstemp(prefix='G03_011_014_结果_' + stamp + '_', suffix='.txt', dir='.')
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
