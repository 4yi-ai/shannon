# Shannon 独立应用与 4YI 内部试用

本阶段仅修改 Shannon。没有修改 Security Center、Wallet 或 xclaw；没有申请商业许可，也没有发布或运行真实扫描。

## 固定上游

2026-11-06 核实官方最新发布仍为 `v3.5.0`，源码基线为
`33dc203b32ef45bca15cc68b5a6c8931d5752236`。目标仓库已包含其后的 6 个上游提交，本次保留并固定在
`8c75a9b5a89ac02b7be8efeca7e129284d37e20f`，改动为文档及错误提示链接，见 `deploy/4yi/upstream.json`。
保留上游 CLI、AGPL 许可、版权和第三方声明，独立应用使用 `deploy/4yi/Dockerfile`。

## 服务结构与持久化

- `web`：Python 标准库 HTTP API、网页和串行扫描监督器；直接启动上游 Node Worker，无 Docker socket、特权容器、hostPath 或子容器。
- `temporal`：固定版本正式 Temporal Server + SQL 后端，未使用 `start-dev` 或已弃用的 `auto-setup`。启动包装器仅初始化全新数据库，已有数据库升级必须显式执行 `migrate`；跨两个数据库持有 PostgreSQL advisory lock，避免并发迁移。单副本适合内部试用；正式运营仍需分离迁移账号与运行账号、启用认证/TLS、备份及 HA。
- `postgres`：Temporal 主库与 visibility 库，独立持久卷。

Web 的 `/app/data` 包含 `tasks.sqlite3`（WAL、FULL 同步）、`tasks/<id>/source.zip`、解压或克隆代码、工作区、模型描述、进度、结构化结果和报告。不同服务不共享文件目录。Web 必须保持单副本，不能让多个监督器同时领取同一 SQLite 队列。

启动时额外持有数据目录的进程锁，防止两个 Web 进程意外同时执行同一队列。独立 Dockerfile 使用 Docker Official Images 在 ECR Public 的 Node 22 Debian 镜像，并固定 manifest digest；PostgreSQL 16.15 Alpine 同样固定官方 ECR digest（声明使用无 tag 的 digest 格式以兼容平台解析器）；原上游 Wolfi Dockerfile 保留给 CLI 使用。

重启后排队任务继续排队。运行中任务不会自动重复攻击：监督器先终止持久化的 Temporal workflow，然后标为失败；取消请求最终标为取消。Temporal 不可达时保留“清理中”，反复重试，不误报已经终止。源码和报告不删除。

本阶段不提供自动恢复中断扫描或自动清理历史；备份 SQLite 时应使用 SQLite backup API 或停服备份，并同时备份任务目录和 PostgreSQL。

## 网络隔离是部署门槛

**默认 `SHANNON_EXECUTION_ENABLED=false`。仅有网址检查或提示词不能限制 Agent 运行期间的任意网络命令。**

应用入口执行 HTTPS、443 端口、精确 origin 白名单和 DNS 地址检查，拒绝私网、云元数据、保留地址、localhost、服务域名、IPv6 映射/过渡地址。运行前再次解析。Git 只支持公开 HTTPS，禁止重定向、子模块递归、非 HTTPS transport、credential helper 和仓库 hook。ZIP 拒绝路径穿越、符号链接、特殊文件、重复路径与压缩炸弹，限制压缩包 32 MiB、解压后 256 MiB、20000 条目。

这些措施仍然**不能**阻止 DNS rebinding、工具直接访问其他网络、目标重定向、目标作为代理、同一 IP 上的其他虚拟主机或模型提示注入。必须在扫描执行进程之外配置默认拒绝的 CNI/防火墙出口策略；同一授权 IP 上如存在未授权虚拟主机，需要独占测试目标或具有主机名约束且不能绕过的出口执行环境。本实现不宣称进程级强沙箱。为在无额外 Linux 权限的容器运行系统 Chromium，配置 `PLAYWRIGHT_MCP_SANDBOX=false`；浏览器没有自身的 Chromium sandbox，不能据此承载不受信任的多租户公共扫描。

`render-network-policy.py` 根据已确认的 namespace、实际工作负载标签、目标/Git/网关的精确公网 IP 输出策略 JSON，不会自动应用。白名单只放授权目标、批准的 Git 主机和实例模型网关；Web 另可访问本安装的 Temporal 7233；Temporal 仅可访问本安装 PostgreSQL 与自身；DNS 仅限集群 DNS。脚本拒绝内网网关地址，内网网关需要额外人工审查的更窄服务策略，不能简单放开 RFC1918。

4yi-app.json 的当前声明格式不能携带 NetworkPolicy。本仓库不修改平台全局策略。因此内部试用必须由现有集群运维入口安装策略，并验证 CNI 真正执行它。若无法配置，保持执行关闭，不能发布为可运行扫描器。环境变量 `SHANNON_EGRESS_POLICY_VERIFIED=true` 只是操作员的验收记录，不会自行创建防火墙。

验收至少包括：对授权目标可连接；DNS rebinding/重定向到私网失败；元数据 `169.254.169.254`、私网、同集群其他租户服务、未授权公网目标、任意 DNS 出口均不可达；目标站点无法作为任意 HTTP 代理。Agent 与控制层在同一安装容器内，因此当前版本只适用于受信内部操作员和受信源码，不能作为不可信用户可运行任意源码的公共多租户扫描服务。

## 模型协议与安装凭据

声明 `LLM_MODEL` Chat 模型槽。平台按安装实例注入 `OPENAI_API_KEY` 与 `OPENAI_API_BASE`（也接受 `OPENAI_BASE_URL`），镜像、声明和源码不含发布者模型密钥。

每个任务生成不含密钥值的 Pi models.json，注册 `fouryi:<LLM_MODEL>`，明确使用 `api: openai-completions`，关闭 developer role、reasoning effort 与 store 参数。不能只更换上游 OpenAI 模型 base URL，因为其默认可能使用 Responses。实际锁定的 Pi harness 通过本地 SSE 模型夹具验证 Chat Completions 和工具调用往返。

自定义模型描述中的价格为零，仅用于协议兼容；真正费用以 4YI 网关账单为准，上游本地费用估算不能用于计费。默认上下文 128000、输出上限 16384，安装前确认所选模型支持工具调用与这些上限。

## Secret 与部署准备

本地离线 Proposal 检查使用实际 xclaw 扫描/生成函数、虚构 source ref，并禁止数据库访问：结果为 `multi_service`、三服务、`blockers=[]`。`SHANNON_API_KEY` 被识别为安装方必填 Secret，`POSTGRES_PASSWORD` 被识别为平台托管随机凭据，网关 key 不列为安装方模型密钥。正式安装应优先使用平台生成的数据库密码并确保 Temporal 收到同一值；不要额外生成一个不同密码覆盖它。

这不是远程 Analyze/Apply 或安装验收。现有警告包括内存、路由别名、流式连接、数据库及旧 CLI 的前端检测提示，需要在实际 Proposal 中核对。

必须通过现有平台 Secret 机制为该安装配置：

| 变量 | 作用 |
| --- | --- |
| `SHANNON_API_KEY` | 至少 32 字符随机独立 API token；网页与后续调用端使用同一实例 token |
| `POSTGRES_PASSWORD` | 每安装随机数据库密码，Postgres 与 Temporal 使用相同值 |
| `OPENAI_API_KEY` / `OPENAI_API_BASE` | 平台运行期注入的实例网关凭据/地址 |
| `LLM_MODEL` | 平台安装模型选择 |

不可假设 Codescan 专用 Secrets 表单适用于 Shannon，也不能把它的共享 key 或固定数据库密码写进声明。Apply 前检查 Proposal 的 consumer secrets 与平台运行时推断。如果现有入口无法为 Shannon 配置应用/数据库 Secret，视为安装阻塞，不能以明文密码绕过。

`4yi-app.json` 当前内部 DNS 假设 slug 为 `shannon`；Apply 前以真实 Proposal 为准改 `TEMPORAL_ADDRESS` 与 `POSTGRES_SEEDS`。公共服务必须只有 Web，Temporal 和数据库都不能公开。健康检查 `/healthz` 快速且无鉴权；它只反映 HTTP 控制层可用，不代表 Temporal/模型可执行。

内部试用的步骤：

1. 本地构建独立镜像和 Temporal 镜像；运行控制层与协议测试。`.github/workflows/standalone.yml` 提供相同的 CI 检查及对应源码归档完整性检查。
2. 代码验收后推送至已确认的 `4yi-ai/shannon`；安装前再确认 4YI 组织、安装方式和授权测试环境。
3. Analyze 核实三服务、两独立 PVC、模型槽、Secret 契约及真实 DNS；先 Review Proposal 再 Apply。
4. 创建固定 commit 的 Release，仅在内部组织安装，执行仍保持关闭。
5. 使用真实实例凭据验证模型工具调用；配置并验证出口隔离；写入精确 `SHANNON_AUTHORIZED_ORIGINS=https://test.example`（多个 origin 逗号分隔）。
6. 通过网络验收后才设置 `SHANNON_EGRESS_POLICY_VERIFIED=true`、`SHANNON_EXECUTION_ENABLED=true`。
7. 用确认过的测试环境验收 ZIP/Git、进度、部分完成、失败、运行中取消、报告下载、服务重启、Pod 重建和两份持久卷。升级后确认历史和文件仍在。

本地控制层无需 Docker，可在设置随机 `SHANNON_API_KEY` 后运行 `python3 -m apps.standalone.server`；默认不会执行扫描。
本地三服务环境使用 `docker compose -f deploy/4yi/compose.yml up --build`，需在环境中设置 API token 与数据库密码。Compose 默认也禁止执行；它没有出口防火墙，不是安全扫描沙箱。

镜像升级前先备份数据库；若需要更新 Temporal schema，使用新 Temporal 镜像执行 `python3 /etc/temporal/standalone-server.py migrate`，成功后再替换常驻服务。正常启动不会隐式升级已有 schema，也会拒绝把新版本数据库交给旧镜像。Temporal 镜像从官方 1.29.1 二进制发布包及同标签源码提取 PostgreSQL schema，构建时校验 SHA-256；保留其 MIT 许可。仅内部网络开放无鉴权的 Temporal gRPC，不映射公网。默认 namespace 由 Web 内部启动检查幂等创建，保留期 7 天；HTTP 健康检查不承担初始化。

`python3 deploy/4yi/smoke.py` 使用隔离的临时 Compose 项目验证三服务、源码归档、非 root Web、SQL-backed Temporal 合成工作流、重启后的工作流/代码/报告及取消；始终关闭扫描，不使用真实模型或目标。测试结束仅清理其自行创建的容器和卷。

## API 契约（后续 PIAQEE 接入）

除 `/healthz`、静态页面与对应源码下载 `/source` 外，所有 API 都要求 `Authorization: Bearer <SHANNON_API_KEY>`，不信任客户端伪造的组织 Header。每个组织安装独立实例和独立 token；本阶段无共享多租户路由。

| 方法与路径 | 返回 |
| --- | --- |
| `GET /api/v1/config` | 实际模型、执行开关和授权 origin |
| `POST /api/v1/tasks` | HTTP 202，持久化后的异步任务 |
| `GET /api/v1/tasks?limit=50&offset=0` | 分页历史，limit 最大 100 |
| `GET /api/v1/tasks/{id}` | 状态、上游进度、终态结果与部分完成原因 |
| `POST /api/v1/tasks/{id}/cancel` | HTTP 202，幂等取消；运行中先进入 cancelling |
| `GET /api/v1/tasks/{id}/reports/markdown` | Markdown 附件 |
| `GET /api/v1/tasks/{id}/reports/pdf` | 可用时返回 PDF，否则 404 |

创建任务的 JSON 必须包含 `target`、`authorization_confirmed: true`，以及 `source_type: "zip"` 和 `zip_base64`，或者 `source_type: "git"`、`repository` 和 `branch`。上传体上限 48 MiB。最多 10 个非终态任务；源码压缩包总配额 1 GiB，任务磁盘使用仍需操作员监控和卷配额保护。

状态：`queued → preparing → running → completed | partial | failed | cancelled`，取消期间为 `cancelling`，无法确认工作流清理时为 `recovering`。只有结构化结果为 completed/partial、退出码 0 且 Markdown 报告存在才认可完成；退出码 0 缺少结果或报告仍是失败。部分完成原因不丢弃。进度是完成/跳过的 Agent 数量，不等于精确耗时百分比。

当前 API token 为实例级权限，可创建任务并读取该实例全部历史；无幂等键、用户级 ACL 或对外共享报告链接。后续接入 PIAQEE 时再定义客户端重试/幂等和轮换策略，不修改 Security Center 代码。

## 对应源码和许可

保留 `LICENSE`、`LICENSES`、`THIRD_PARTY_NOTICES.md` 与上游版权。构建将当前适配源码（不含 .git、依赖、运行数据和 .env）打包为 `/usr/share/shannon/source.tar.gz`，网页提供 `/source` 下载。每次 Release 应核验下载归档包含本次所有修改、构建文件与锁文件，和运行镜像一一对应。

发布前核对 AGPL 第 13 条对通过网络交互用户提供对应源码的义务、第三方再分发要求及源码归档完整性。内部试用不等于自动豁免许可义务；不申请商业许可，也不修改 xclaw 的全局许可策略。

## 本轮验证与尚未完成项

- 锁定依赖安装、上游 Worker TypeScript 构建、前端 JavaScript 语法检查通过。
- 11 项 Python 测试通过，包括真实 HTTP 进程重启后的历史、代码、报告读取，以及第二监督器进程被锁拒绝。
- 实际锁定 Pi runtime + 本地模型夹具验证：自定义模型注册、实例 Bearer token、`/chat/completions` SSE、工具调用及工具结果回传通过。没有调用真实模型或扫描真实目标。
- 本机 Chrome/Playwright 验证：鉴权、任务列表/详情、Markdown 下载、Git 表单、创建、排队取消、桌面与 390px 手机布局通过；无 JavaScript 运行错误。测试任务和报告均为夹具数据。
- xclaw 实际声明解析器、仓库扫描器、离线 Proposal 生成检查通过，没有修改 xclaw 文件或访问平台数据库。
- 本地 ARM64 Web/Temporal 镜像构建通过；最终三服务使用 PostgreSQL 16.15，容器冒烟测试通过：非 root、无 Docker socket、API 鉴权、系统 Chromium 空白页、完整源码归档、SQL schema 初始化、合成工作流完成、Temporal 重启后的工作流持久化及终止、Web 重启后的历史/代码/报告读取。所有任务均为合成夹具，不访问真实目标。
- GitHub Actions 的 AMD64 Worker/协议/11 项 Python 测试、Web/Temporal 镜像构建、三服务重启持久化验收及对应源码归档检查全部通过：[验收记录](https://github.com/4yi-ai/shannon/actions/runs/42178134837)。应用代码验收提交为 `c1c68ab9f965542e03f79fa5c7630c26f0814813`。
- 本次交付为独立应用代码与部署准备，不代表已在 4YI 发布或安装。真实安装组织、实际 Proposal、实例模型调用、CNI 网络隔离、PVC Pod 重建及授权目标扫描仍待部署验收；未运行真实扫描。
