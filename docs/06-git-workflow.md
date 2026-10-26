# Git保存与上传

## 三个动作

| 动作 | 保存到哪里 | 含义 |
| --- | --- | --- |
| 保存文件 | 本机工作目录 | 编辑器把内容写入文件 |
| commit | 本地Git仓库 | 把已暂存的改动形成可回看的版本 |
| push | GitHub远程仓库 | 上传本地提交及相应分支更新 |

所以：**push成功后，对应提交已同步到GitHub。** 未commit的文件、不在提交中的文件、被忽略的文件不会被顺带上传。本项目原始证据刻意留在本地，仍需独立备份。

## 首次提交

在本项目根目录打开终端，先确认当前路径，再执行：

```powershell
git init -b main
git status --short
git add README.md NOTICE.md .gitignore .gitattributes scripts docs cases examples tests
git diff --cached --stat
git diff --cached --check
git diff --cached
git commit -m "docs: 整理主机基线检查脚本、判定方法和复测案例"
```

若Git提示缺少身份，配置真实希望出现在提交中的姓名与邮箱；可使用GitHub账号显示的noreply邮箱。不要随意使用别人身份。

## 连接远程并上传

本项目的仓库名为`safe-check`（展示名称safe check），已由所有者指定为公开。首次创建空仓库时可不预置README，减少首次历史冲突。当前仓库地址如下：

```powershell
git remote add origin https://github.com/2682812882npc-star/safe-check.git
git remote -v
git push -u origin main
```

如果已经配置origin，先查看现有地址；不要重复添加或擅自改到别人的仓库。已有远程历史时先拉取并检查，不使用强制push覆盖。

## 确认上传成功

```powershell
git status
git rev-parse HEAD
git ls-remote origin refs/heads/main
```

核对本地HEAD和远程main输出的提交哈希一致，再到GitHub查看文件。push报错或只在本地commit，均不算完成远程保存。

## 后续每个小阶段

修改 → 检查差异及证据边界 → 做必要验证 → add指定文件 → commit → push → 核对远程提交。

比较大的改动先建分支。AI自动commit/push前，应约定哪些目录可提交、如何验证、哪些内容只能本地存。本次首次发布由所有者单独指定，没有设置后续自动上传。

首次公开提交使用本仓库范围内的GitHub隐私邮箱；未修改本机全局Git身份。公开用户名、提交时间和提交内容仍可在GitHub查看。
