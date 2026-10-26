#!/usr/bin/env bash
# 仅在已确认的目标Ubuntu运行；查询配置并保存本地TXT。
if ! command -v python3 >/dev/null 2>&1; then
  printf '%s
' '缺少python3，未执行检查；不自动安装。' >&2
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
    (1, '登录后提示内容', '1.6.1', '161–164', '符合本地文案策略；不含系统信息标记'),
    (2, '本地登录前提示内容', '1.6.2', '165–166', '符合本地文案策略；不含系统信息标记'),
    (3, '登录后提示文件权限', '1.6.4', '169–170', '/etc/motd若存在：UID/GID为0，权限不宽于0644'),
    (4, '本地登录前提示文件权限', '1.6.5', '171–172', '/etc/issue：UID/GID为0，权限不宽于0644'),
]

def markers(text, motd=False):
    pattern = r'\\[vrms]|\bubuntu\b' if motd else r'\\[vrms]|ubuntu'
    return [(n, sorted(set(re.findall(pattern, line, re.I))))
            for n, line in enumerate(text.splitlines(), 1)
            if re.search(pattern, line, re.I)]

def permission_result(record, optional=False):
    if record['state'] == 'absent':
        return ('符合', '文件不存在；本条原文允许缺省') if optional else ('不符合', '必查文件不存在')
    if record['state'] != 'ok':
        return '待核实', record['error']
    uid, gid, mode = record['meta']
    good = uid == 0 and gid == 0 and (mode & ~0o644) == 0
    return ('符合' if good else '不符合'), 'UID={}；GID={}；权限={:04o}'.format(uid, gid, mode)

def content_result(records, gaps, motd=False):
    hits = []
    for path, record in records.items():
        for n, found in record.get('hits', []):
            hits.append('{}:{} [{}]'.format(path, n, '、'.join(found)))
    errors = gaps + [p + '：' + r['error'] for p, r in records.items() if r.get('error')]
    errors += [p + '：' + r['read_error'] for p, r in records.items() if r.get('read_error')]
    if hits:
        return '不符合', '；'.join(hits), '发现系统信息标记' + ('；另有读取缺口，见证据' if errors else '')
    if errors:
        return '待核实', '；'.join(errors), '存在读取或覆盖缺口，不能判为符合'
    count = sum(r['state'] == 'ok' and not r.get('read_error') for r in records.values())
    if not count:
        return '待核实', '未发现可读提示文件', '需确认未使用提示是否符合本地策略' if motd else '未取得本地登录前提示内容'
    return '待人工确认', '已查{}个文件，未检出指定系统信息标记'.format(count), '文案是否符合本地策略尚未确认；不推定整项符合'

def main():
    if sys.platform != 'linux':
        raise SystemExit('仅在目标Ubuntu运行；未执行任何采集。')
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['LC_ALL'] = 'C'
    os.umask(0o077)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    fd, proof_name = tempfile.mkstemp(prefix='G03_001_004_证据_' + stamp + '_', suffix='.txt', dir='.')
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
        log('范围及边界', 'G03-001～004；仅读静态登录提示及文件元数据，不执行动态MOTD脚本；不执行sshd/-T/-t/ssh连接，不读取密钥、密码哈希及密码历史。', 0)
        identity, rc = run(['uname', '-s', '-n', '-r', '-m'])
        if rc or identity != 'Linux lab-ubuntu20 5.4.0-216-generic x86_64':
            raise OSError('身份与已确认资产不一致，停止套用基线')
        distro, rc = run(['awk', '/^(ID|VERSION_ID)=/ {print}', '/etc/os-release'])
        if rc or not re.search(r'^ID="?ubuntu"?$', distro, re.M) or not re.search(r'^VERSION_ID="?20\.04"?$', distro, re.M):
            raise OSError('未确认Ubuntu 20.04')



        records = {}

        def inspect(path, motd=False):
            path = Path(path)
            record = {'state': 'error', 'error': ''}
            try:
                safe_file(path.parent, directory=True)
                try:
                    path.lstat()
                except FileNotFoundError:
                    record['state'] = 'absent'
                    log('文件存在性：' + str(path), '已确认父目录可读；文件不存在', 0)
                    return record
                safe_file(path)
                st = path.stat()
                record.update(state='ok', meta=(st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)))
                log('文件元数据：' + str(path), 'UID={} GID={} mode={:04o}'.format(*record['meta']), 0)
            except (OSError, UnicodeError) as exc:
                record['error'] = str(exc)
                log('文件查询失败：' + str(path), str(exc), 1)
                return record
            try:
                fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, 'rb') as f:
                    now = os.fstat(f.fileno())
                    if not stat.S_ISREG(now.st_mode) or (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino):
                        raise OSError('文件类型或对象在采集期间变化')
                    data = f.read(1024 * 1024 + 1)
                if len(data) > 1024 * 1024:
                    raise OSError('文件超过1MiB，本批不作完整内容判断')
                record['hits'] = markers(data.decode('utf-8'), motd)
                filtered = '\n'.join('行{}：{}'.format(n, '、'.join(values)) for n, values in record['hits'])
                log('内容匹配：' + str(path), filtered or '未匹配；只记录指定标记，不保存完整文案', 0)
            except (OSError, UnicodeError) as exc:
                record['read_error'] = str(exc)
                log('内容读取失败：' + str(path), str(exc), 1)
            return record

        records['/etc/motd'] = inspect('/etc/motd', True)
        records['/etc/issue'] = inspect('/etc/issue')
        motd_records = {'/etc/motd': records['/etc/motd']}
        gaps = []
        folder = Path('/etc/motd.d')
        try:
            safe_file(folder.parent, directory=True)
            try:
                folder.lstat()
            except FileNotFoundError:
                log('MOTD目录', '/etc/motd.d不存在', 0)
            else:
                safe_file(folder, directory=True)
                names = sorted(p for p in folder.iterdir() if not p.name.startswith('.'))
                if len(names) > 100:
                    raise OSError('目录超过100项，本批停止枚举并保留覆盖缺口')
                log('MOTD目录枚举', '\n'.join(str(p) for p in names) or '目录为空', 0)
                for path in names:
                    motd_records[str(path)] = inspect(path, True)
        except (OSError, UnicodeError) as exc:
            gaps.append('/etc/motd.d：' + str(exc))
            log('MOTD目录查询失败', str(exc), 1)

        assessed = {
            1: content_result(motd_records, gaps, True),
            2: content_result({'/etc/issue': records['/etc/issue']}, []),
        }
        for index, path, optional in [(3, '/etc/motd', True), (4, '/etc/issue', False)]:
            verdict, actual = permission_result(records[path], optional)
            assessed[index] = (verdict, path + '：' + actual, '')
        lines = ['G03-001～004｜本地登录提示及权限',
                 '时间：' + datetime.now().astimezone().isoformat(timespec='seconds'),
                 '依据：CIS Ubuntu 20.04 LTS v3.0.0 / Level 1 Server',
                 '范围：静态MOTD、issue；不运行update-motd脚本，不验证实际登录画面。']
        counts = {}
        for index, name, cis, pages, rule in ITEMS:
            verdict, actual, why = assessed[index]
            counts[verdict] = counts.get(verdict, 0) + 1
            lines += ['', '[G03-{:03d}] {} | {}'.format(index, verdict, name),
                      '  基线：CIS {} / p.{}；推荐：{}'.format(cis, pages, rule),
                      '  实际：' + actual]
            if why:
                lines += ['  说明：' + why]
        lines += ['', '本批统计：' + '；'.join(k + str(v) + '项' for k, v in counts.items()),
                  '本批4项；G03共29项，其他条目尚未在本批检查。',
                  '详细证据：' + str(Path(proof_name).absolute())]
        fd, summary = tempfile.mkstemp(prefix='G03_001_004_结果_' + stamp + '_', suffix='.txt', dir='.')
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
