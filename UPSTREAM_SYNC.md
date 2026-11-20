# 跟随上游同步指南

本仓库是 [jeessy2/ddns-go](https://github.com/jeessy2/ddns-go) 的 fork。上游功能更新频繁，本仓库只保留少量 fork 专属改动；同步的目标是**定期把上游 master 合并进来，同时保住 fork 改动**。

## 一、准备（只需一次）

```bash
# 确认 upstream remote 指向官方仓库
git remote add upstream https://github.com/jeessy2/ddns-go.git
git remote -v   # 应同时看到 origin（你的 fork）和 upstream
```

## 二、本地 rebase 跟随上游

```bash
git fetch upstream master
git switch master                    # 或 main，按你的分支名
git rebase upstream/master           # 把你 fork 的提交重放到上游最新提交之后
go test ./...                        # 验证同步后功能完整
git push --force-with-lease origin master   # rebase 改写了历史，必须强推；--force-with-lease 更安全
```

如果不想改写历史，也可以用合并方式（会多一个 merge commit，推送无需强推）：

```bash
git fetch upstream master
git switch master
git merge --no-edit upstream/master
go test ./...
git push origin master
```

仓库还提供了一个 GitHub Actions 工作流 `.github/workflows/sync-upstream.yml`：支持手动 `workflow_dispatch` 触发，以及每周一 02:00 UTC（北京时间 10:00）定时执行。它会以完整历史 checkout、添加 upstream remote、fetch master、尝试 rebase、跑 `go test ./...`。注意：该工作流是**检测式同步**，不会把结果推送回 fork；一旦 rebase 冲突就会让 workflow 失败，并在日志和 Job summary 中打印解决步骤。看到失败后按下面第三节在本地处理。这里没有使用 `gh issue create` 自动开 issue，因为那需要额外的 token 权限（`issues: write`），而默认的 `GITHUB_TOKEN` 权限更保守；失败日志已给出明确指引。

## 三、冲突时如何保留 fork 改动

rebase 遇到冲突时，Git 会停下并列出冲突文件。处理原则：**上游代码作为基底，fork 专属改动重新叠加**。

```bash
git status                    # 查看 "both modified" 的文件
# 逐个打开冲突文件，删除 <<<<<<< / ======= / >>>>>>> 标记，
# 保留上游的新逻辑，同时把 fork 的改动重新放回去（参考第四节清单）
git add <冲突文件>
git rebase --continue         # 继续重放剩余提交
# 若某次 fork 提交在 upstream 中已被上游实现、无需重放：
git rebase --skip
# 想彻底回到 rebase 前的状态：
git rebase --abort
```

冲突解决后必须再次运行 `go test ./...`，确认 fork 的安全加固仍然有效（登录限流、CSRF、登出清理等）。

## 四、fork 改动文件清单（同步时重点核对）

下列文件包含 fork 专属改动，rebase/merge 冲突时要重点确认它们仍保留我们的意图：

| 文件 | 改动内容 |
| --- | --- |
| `Dockerfile.optimized` | fork 专属优化镜像构建：静态编译、非 root 用户、`/config` 可写目录、tini/tzdata/ca-certificates，以及基于 `/healthz` 的 busybox wget 健康检查。 |
| `.github/workflows/docker-publish.yml` | fork 专属 GHCR 发布流程，含镜像标签以及 SBOM / 漏洞扫描 / 签名等供应链步骤。 |
| `web/security.go` |  fork 新增：按 IP 的登录限流与 CSRF token 相关实现。 |
| `web/login.go` | fork 修改：登录流程接入限流与 CSRF 校验。 |
| `web/auth.go` | fork 修改：鉴权逻辑接入 CSRF/会话相关改动。 |
| `static/utils.js` | fork 修改：前端请求携带/处理 CSRF token。 |
| `web/logout.go` | fork 修改：登出时清理会话/cookie（历史上曾修复覆盖系统 cookie 的问题）。 |
| `main.go` 中的 `/healthz` | fork 新增的健康检查端点（供容器 healthcheck 使用）。若同步后上游新增了同名或类似端点，以不破坏容器健康检查为前提处理冲突。 |

> 注：`web/logout.go` 和 `main.go` 的具体改动可能已部分被上游吸收；每次同步请以 `git diff upstream/master...HEAD`（rebase 前）或 `git log upstream/master..HEAD` 的实际结果为准。

## 五、同步检查清单

- [ ] `git fetch upstream master` 成功
- [ ] rebase 或 merge 完成，无遗留冲突标记
- [ ] `go test ./...` 通过
- [ ] 第四节清单里的 fork 改动逐项仍在（必要时手工对比）
- [ ] Dockerfile.optimized 的 healthcheck 指向 `/healthz`
- [ ] 推送后确认 GitHub Actions（test / docker-publish / sync-upstream）为绿色
