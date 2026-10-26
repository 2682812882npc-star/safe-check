# safe check · 主机安全基线检查与加固实验

Windows Server 2019 与 Ubuntu 20.04 个人实验资料，整理检查脚本、判定方法及代表性整改复测案例。

核心流程：确定范围 → 采集证据 → 对照基线 → 人工核实 → 备份与整改 → 复测 → 记录回退。

## 从哪里看

| 内容 | 入口 |
| --- | --- |
| 项目范围、历史进度、验证边界 | [范围与状态](docs/01-scope-and-status.md) |
| 符合、不符合、未检查怎么判断 | [统一判定方法](docs/02-judgment-method.md) |
| Windows脚本使用与273项映射 | [Windows检查](docs/03-windows-checks.md) |
| Ubuntu九领域方法及脚本覆盖 | [Ubuntu检查](docs/04-ubuntu-checks.md) |
| 修改、复测与回退案例 | [10个案例](cases/README.md) |
| 整改记录、人工复核记录格式 | [示例与模板](examples/README.md) |
| 本次整理与验证 | [验证记录](docs/05-verification.md) |
| 如何commit、push到GitHub | [Git操作](docs/06-git-workflow.md) |
| 脱敏、来源及未收入的附件 | [整理说明](docs/07-publication-notes.md) |
| 首次公开前的隐私复查 | [隐私复查记录](docs/08-privacy-review.md) |

## 目录

```text
host-baseline-lab/
├── scripts/windows/        # PowerShell、C#、清单、未填写的运行记录模板
├── scripts/ubuntu/         # 15个批次/补查脚本
├── docs/mappings/          # Windows273项映射、全表范围台账、Ubuntu方法表
├── cases/                  # Ubuntu与Windows各5个代表案例
├── examples/               # 可复制的整改/复核模板及明确标注的合成示例
├── tests/                  # 离线测试说明与本次验证摘要
├── .gitattributes
└── .gitignore
```

## 使用边界

- 资料来自个人实验历史记录；2026-10-26进行了文件整理及离线验证，没有重新进入目标虚拟机采集。
- Windows清单含273项明确要求，260项支持配置层面的自动判断，2项部分自动，11项静态不适用。数量表示设计范围，实际结果取决于当次采集。
- Ubuntu原笔记覆盖九个领域；随包15个脚本只覆盖G01～G04、G05的一部分及PAM引用补查。完整领域记录不等于完整脚本覆盖。
- 脚本按本机读取与本地保存结果设计。运行身份限制保留，公开版主机名是示例；先看平台使用说明。
- 配置一致、离线模拟通过、实际功能验证是三种不同证据。未验证的部分已在各案例列出。

首次阅读建议：先看[案例索引](cases/README.md)，再对照[判定方法](docs/02-judgment-method.md)阅读源码。
