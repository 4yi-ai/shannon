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

## 开发内测模式与网络边界（2026-11-08 更新）

用户已明确接受当前版本作为“受信任开发内测”使用。根声明默认 `SHANNON_EXECUTION_MODE=trusted_dev`、`SHANNON_EXECUTION_ENABLED=true`：正常安装并通过 4YI 登录后，即可从页面填写目标、上传 ZIP / 公开 Git 源码及登录信息，勾选授权后创建任务。无需额外设置 `SHANNON_EGRESS_POLICY_VERIFIED`，也无需为每个目标手工配置 `SHANNON_AUTHORIZED_ORIGINS`。若已有实例显式设置了关闭开关，仍尊重该设置；升级需重新读取新声明并更新安装实例，而不是继续使用旧 Release。

每个任务保存页面提交的目标及 `authorized_origin`。应用入口和执行前执行 HTTPS、443 端口、DNS 公网地址检查，拒绝私网、云元数据、保留地址、localhost、服务域名和 IPv6 映射/过渡地址。登录页面必须与本次目标同源。可选 `SHANNON_AUTHORIZED_ORIGINS` 保留作部署方主动收窄范围的策略；未设置时接受页面提交并确认授权的公网 HTTPS 目标。ZIP/Git 安全检查继续生效。

这些是入口与执行前检查，**不是 Agent 任意命令的运行期网络强隔离**。不保证拦截工具后续直连、DNS rebinding、目标重定向、目标代理、同 IP 其他虚拟主机或提示注入产生的流量。本版扫描器仅供受信操作员和受信源码的开发内测，不能当作不可信用户可执行任意源码的公共多租户扫描服务；系统 Chromium 仍使用 `PLAYWRIGHT_MCP_SANDBOX=false`，没有浏览器自身沙箱。放宽这项部署门槛是本次确认的实际取舍，没有宣称平台网络已被验证，也不修改 xclaw、Wallet 或 Security Center。

如需原先的严格部署门槛，显式选择 `SHANNON_EXECUTION_MODE=isolated`。该模式只有在执行开关开启、平台安装上下文有效且 `SHANNON_EGRESS_POLICY_VERIFIED=true` 时允许执行；缺少确认则保持 Web 可用但关闭扫描。未知模式同样关闭扫描。确认标记不会创建防火墙。4YI 当前声明不支持携带 NetworkPolicy，非 root 容器的无特权网络命名空间探测也被拒绝；因此不能把一次环境变量修改视为自动建立沙箱。

`render-network-policy.py` 仍用于严格部署：按已确认的 namespace、工作负载标签、授权目标/Git/模型网关公网 IP 生成策略 JSON，不会自动应用。策略限制 Web 入站仅来自受信平台路由器、限制后端通信和出口，需要现有运维入口应用并验收 CNI；HTTPS 同 IP 虚拟主机约束还需专门出口执行环境。此类部署需验证私网、元数据、其他租户、重定向和 DNS 重绑定拦截。开发内测模式并未完成这些验收。

## 模型协议与安装凭据

声明 `LLM_MODEL` Chat 模型槽。平台按安装实例注入 `OPENAI_API_KEY` 与 `OPENAI_API_BASE`（也接受 `OPENAI_BASE_URL`），镜像、声明和源码不含发布者模型密钥。

每个任务生成不含密钥值的 Pi models.json，注册 `fouryi:<LLM_MODEL>`，明确使用 `api: openai-completions`，关闭 developer role、reasoning effort 与 store 参数。不能只更换上游 OpenAI 模型 base URL，因为其默认可能使用 Responses。实际锁定的 Pi harness 通过本地 SSE 模型夹具验证 Chat Completions 和工具调用往返。

自定义模型描述中的价格为零，仅用于协议兼容；真正费用以 4YI 网关账单为准，上游本地费用估算不能用于计费。默认上下文 128000、输出上限 16384，安装前确认所选模型支持工具调用与这些上限。

## Secret 与部署准备

之前的离线 Proposal 检查验证了三服务拓扑。当前版本不再读取或要求 `SHANNON_API_KEY`；重新 Analyze 时应检查新 Proposal 不再要求该旧密钥。`POSTGRES_PASSWORD` 仍由平台托管，各服务须使用同一安装实例的值；网关凭据由平台注入。

这不是远程 Analyze/Apply 或安装验收。现有警告包括内存、路由别名、流式连接、数据库及旧 CLI 的前端检测提示，需要在实际 Proposal 中核对。

必须通过现有平台 Secret 机制为该安装配置：

| 变量 | 作用 |
| --- | --- |
| `SHANNON_AUTH_MODE=4yi_sso` | 本版网页使用 4YI 会话，无需用户设置或填写应用 API Key |
| `POSTGRES_PASSWORD` | 每安装随机数据库密码，Postgres 与 Temporal 使用相同值 |
| `OPENAI_API_KEY` / `OPENAI_API_BASE` | 平台运行期注入的实例网关凭据/地址 |
| `LLM_MODEL` | 平台安装模型选择 |

不可假设 Codescan 专用 Secrets 表单适用于 Shannon，也不能把它的共享 key 或固定数据库密码写进声明。Apply 前检查 Proposal 的 consumer secrets 与平台运行时推断。如果现有入口无法为 Shannon 配置应用/数据库 Secret，视为安装阻塞，不能以明文密码绕过。

`4yi-app.json` 当前内部 DNS 假设 slug 为 `shannon`；Apply 前以真实 Proposal 为准改 `TEMPORAL_ADDRESS` 与 `POSTGRES_SEEDS`。公共服务必须只有 Web，Temporal 和数据库都不能公开。Web 健康路径为 `/shannon-healthz`，避免被平台路由器的全局 `/healthz` 截获；响应包含 `service: shannon`、`api_configured`、`execution_enabled`。200 只证明控制层可用，不代表凭据、Temporal 或模型就绪。旧 `/healthz` 保留作应用直连兼容路径。

内部试用的步骤：

1. 本地构建独立镜像和 Temporal 镜像；运行控制层与协议测试。`.github/workflows/standalone.yml` 提供相同的 CI 检查及对应源码归档完整性检查。
2. 代码验收后推送至已确认的 `4yi-ai/shannon`；安装前再确认 4YI 组织、安装方式和授权测试环境。
3. Analyze 核实三服务、两独立 PVC、模型槽、Secret 契约及真实 DNS；先 Review Proposal 再 Apply。
4. 创建固定 commit 的 Release，仅在受信开发组织安装；新声明已默认启用开发内测扫描。
5. 使用实例凭据验证模型工具调用。在页面提交已授权的公网测试目标、源码和必要登录信息，不需要额外填写目标白名单。
6. 若选择严格隔离部署，按上一节验收外部网络策略后再开启；开发内测默认不走这一步。
7. 用确认过的测试环境验收 ZIP/Git、进度、部分完成、失败、运行中取消、报告下载、服务重启、Pod 重建和两份持久卷。升级后确认历史和文件仍在。

本地控制层无需 Docker，可运行 `python3 -m apps.standalone.server` 查看网页；任务接口仍需受信平台代理及安装上下文，不能直接在浏览器伪造身份。自动化测试使用隔离的模拟平台身份。
本地三服务环境使用 `docker compose -f deploy/4yi/compose.yml up --build`，需配置安装域名、组织 ID 和数据库密码，并经受信 SSO 代理访问。Compose 与根声明一样默认启用开发内测；它没有出口防火墙，不是扫描沙箱。仅查看页面时可设置 `SHANNON_EXECUTION_ENABLED=false`。

镜像升级前先备份数据库；若需要更新 Temporal schema，使用新 Temporal 镜像执行 `python3 /etc/temporal/standalone-server.py migrate`，成功后再替换常驻服务。正常启动不会隐式升级已有 schema，也会拒绝把新版本数据库交给旧镜像。Temporal 镜像从官方 1.29.1 二进制发布包及同标签源码提取 PostgreSQL schema，构建时校验 SHA-256；保留其 MIT 许可。仅内部网络开放无鉴权的 Temporal gRPC，不映射公网。默认 namespace 由 Web 内部启动检查幂等创建，保留期 7 天；HTTP 健康检查不承担初始化。

`python3 deploy/4yi/smoke.py` 使用隔离的临时 Compose 项目验证三服务、源码归档、非 root Web、SQL-backed Temporal 合成工作流、重启后的工作流/代码/报告及取消；始终关闭扫描，不使用真实模型或目标。测试结束仅清理其自行创建的容器和卷。

## API 契约（后续 PIAQEE 接入）

本版取消网页手工 Key 流程。除健康检查、静态页面和对应源码外，任务接口要求受信 4YI 路由器验证后的 SSO 身份；旧 Bearer Key 不再被接受，声明移除 `/api` Bearer 透传。本阶段仍为每组织独立实例，PIAQEE 外部调用鉴权延期。

平台向消费者安装注入 `XCLAW_APP_HOSTNAME`、`XCLAW_CONSUMER_ORG_ID`，应用校验代理注入的会话、用户、路由、应用 ID 以及安装组织、域名和 HTTPS 上下文。写操作要求同源 Origin。只收到组织头或缺少安装上下文时拒绝访问，不降级为匿名 API；未配置好安装上下文时不执行扫描。

**信任边界：这些身份头不是签名。** 本地核对的 xclaw-router 会删除客户端全部 `x-xclaw-*` 头，验证平台会话后重新注入身份。应用 Service 必须保持私有，只允许受信路由器进入，不能直接公开 Pod/Service 或允许其他租户绕过代理直连。`render-network-policy.py` 新增必填的路由器 namespace 与工作负载标签参数，生成限制 Web 入站的策略；需由运维确认标签并验证 CNI。不能把浏览器可以随意提供的组织 Header 当作身份凭据。

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

当前平台登录用户可访问自己组织安装实例中的任务；本版尚无实例内部的用户级 ACL、幂等键或公开分享报告链接，不修改 Security Center 代码。

### 后续 PIAQEE 接入待办（本版明确延期）

- [ ] 设计独立的机器调用凭据或短期签名，定义租户绑定、权限范围、轮换及撤销；不能复用模型网关 key，也不能把凭据交给网页用户手填。
- [ ] 再为机器调用开放受控路由与鉴权；当前移除了 Bearer 透传，不可直接用旧 Key 调用。
- [ ] 定义创建任务的幂等键、重试、进度同步和报告读取权限，并补齐跨租户拒绝测试。
- [ ] 单独确定 PIAQEE/Security Center 接入范围；本阶段仅完成 4YI 网页使用流程，不修改上述系统。

## 对应源码和许可

保留 `LICENSE`、`LICENSES`、`THIRD_PARTY_NOTICES.md` 与上游版权。构建将当前适配源码（不含 .git、依赖、运行数据和 .env）打包为 `/usr/share/shannon/source.tar.gz`，网页提供 `/source` 下载。每次 Release 应核验下载归档包含本次所有修改、构建文件与锁文件，和运行镜像一一对应。

发布前核对 AGPL 第 13 条对通过网络交互用户提供对应源码的义务、第三方再分发要求及源码归档完整性。内部试用不等于自动豁免许可义务；不申请商业许可，也不修改 xclaw 的全局许可策略。

## 本轮验证与尚未完成项

- 锁定依赖安装、上游 Worker TypeScript 构建、前端 JavaScript 语法检查通过。
- 13 项 Python 测试通过，包括真实 HTTP 进程重启后的历史、代码、报告读取，以及第二监督器进程被锁拒绝。
- 实际锁定 Pi runtime + 本地模型夹具验证：自定义模型注册、实例 Bearer token、`/chat/completions` SSE、工具调用及工具结果回传通过。没有调用真实模型或扫描真实目标。
- 本机 Chrome/Playwright 验证：鉴权、任务列表/详情、Markdown 下载、Git 表单、创建、排队取消、桌面与 390px 手机布局通过；无 JavaScript 运行错误。测试任务和报告均为夹具数据。
- xclaw 实际声明解析器、仓库扫描器、离线 Proposal 生成检查通过，没有修改 xclaw 文件或访问平台数据库。
- 本地 ARM64 Web/Temporal 镜像构建通过；最终三服务使用 PostgreSQL 16.15，容器冒烟测试通过：非 root、无 Docker socket、API 鉴权、系统 Chromium 空白页、完整源码归档、SQL schema 初始化、合成工作流完成、Temporal 重启后的工作流持久化及终止、Web 重启后的历史/代码/报告读取。所有任务均为合成夹具，不访问真实目标。
- GitHub Actions 的 AMD64 Worker/协议/11 项 Python 测试、Web/Temporal 镜像构建、三服务重启持久化验收及对应源码归档检查全部通过：[验收记录](https://github.com/4yi-ai/shannon/actions/runs/42178134837)。应用代码验收提交为 `c1c68ab9f965542e03f79fa5c7630c26f0814813`。
- 本次交付为独立应用代码与部署准备，不代表已在 4YI 发布或安装。真实安装组织、实际 Proposal、实例模型调用、CNI 网络隔离、PVC Pod 重建及授权目标扫描仍待部署验收；未运行真实扫描。


## 发布失败排查：密钥、已有数据库与 Temporal 探针（2026-11-07 更新）

历史版本曾要求用户填写 32 字符的应用 Key。此问题已由本版 4YI 平台登录方式取代，不再要求设置或填写该 Key。缺少平台安装上下文时 Web 仍可启动，但受保护 API 返回 503 且禁止扫描；有效安装上下文下，缺少受信 SSO 身份的请求返回 401。

若 PostgreSQL 持续报告 `password authentication failed for user "temporal"`，两个容器的环境变量相同不代表数据库角色密码相同：`POSTGRES_PASSWORD` 只在空数据目录初始化时设置角色密码，更新 Secret 不会修改已有角色。先确认挂载的是预期 PVC、数据库和角色，并备份已有数据库；不要删除、重新初始化或替换 PVC。

由有权限的操作员选择以下一种路径：

1. 若能取得并验证数据库当前有效的旧凭据，将该安装的 PostgreSQL/Temporal Secret 同步回有效凭据，再滚动更新相关服务。
2. 若需要轮换，用已有的授权数据库管理员连接，通过交互式 `psql` 的 `\password temporal` 更新角色密码，同时协调安装实例的托管 Secret 与 Temporal 配置使用同一新密码。不要把密码放在 shell 参数、SQL 文件、构建参数或发布日志中。无法取得管理员访问权限时交由数据库管理员处理，不能清空卷绕过。

新版 Temporal 声明 `healthPath: "/healthz"`，不再依赖平台将 HTTP 探针转成 TCP。镜像内非 root NGINX 在同一个 7233 端口提供 HTTP/1 健康检查和 HTTP/2 gRPC，gRPC 转发到同容器回环地址 17233。健康处理器检查实际 Temporal 端口与 PostgreSQL `SELECT 1`，未就绪返回 503，就绪返回 200。无需新增 Service 端口、共享目录或平台代码改动。必须确认最终 Deployment 使用 7233 `/healthz` HTTP 探针；若仍为旧 `/`，重新 Analyze、Apply 并创建使用最新提交的 Release。

重新发布前让 Proposal 重新读取最新声明，检查实例 Secret 和已有 PVC 绑定；不能只刷新旧 Release 的 Publish Gate。发布后验证 Web/Temporal/PostgreSQL Pod 稳定 Ready、重启次数不持续增加、Temporal 日志无认证失败，再查看该 Release 的 smoke 每项检查结果。通过 SSO 的应用根路径应返回实际 Shannon HTML，健康路径应确认来自该 Web Pod；SSO 401 或来源不明的 `/healthz` 200 都不足以证明恢复。开发内测按当前默认模式验证实例模型并使用授权目标；严格隔离部署仍需完成出口隔离验收。

## 与成功部署项目再次对照

2026-11-07 只读核对了 `pentagi` 的 `origin/4yi-marketplace` 声明和指南、`piaqee-codescan` 的声明及 API 鉴权实现、`trivy` 声明。保留单公网 Web、内部后端、独立 PVC、非 root 与每实例凭据；没有复制示例固定数据库密码。

- Web 参照 Codescan 分离 HTTP 启动和 API 授权：凭据不合规不再 CrashLoop，但拒绝所有 API，禁止扫描。
- Temporal 按 PentAGI 内部 executor 的显式 HTTP 健康接口方式适配现有平台。使用 [NGINX gRPC 模块](https://nginx.org/en/docs/http/ngx_http_grpc_module.html)与 [HTTP/2 支持](https://nginx.org/en/docs/http/ngx_http_v2_module.html)在同一声明端口提供 HTTP 探针与 gRPC；NGINX 或 Temporal 子进程退出时监督器停止另一个子进程，收到 SIGTERM 时协调关闭。后端端口仅监听回环地址。
- Compose 对每服务施加与声明一致的 1 CPU、2 GiB 限制。验收包含相同 Secret/PVC 下强制重建 Postgres 与 Temporal、工作流持久化、错误密码时 HTTP 503，以及恢复原 Secret 后不删除卷即可重新就绪。
- 本地 xclaw 当前代码在 `githubCatalogRuntimeHardening` 启用时保留重新 Apply 前的托管 Postgres 密码。Shannon 使用统一 `POSTGRES_PASSWORD` 契约；不会猜测、自动重置已有角色密码，也不保存另一份凭据来掩盖漂移。已经不匹配的旧实例仍需按上一节同步有效凭据，镜像无法恢复数据库中的原明文密码。

这些检查不等于线上安装验收。发布前仍需确认 API 配置、真实实例模型和外部网络隔离；没有在本次改造中操作线上 Secret、数据库或 PVC。


## 被测网站登录（2026-11-07）

4YI 平台登录和被测网站登录相互独立。创建任务时可选“测试需要登录的功能”，填写同源 HTTPS 登录页面、专用测试账号和密码、可选 Base32 TOTP 密钥、每行一步的登录流程及成功条件。流程用 `$username`、`$password`、`$totp` 引用凭据。成功条件支持地址包含、地址完全匹配、页面包含文字。提交成功后清空页面的密码与 TOTP；不存入浏览器 localStorage。

本版通过原生 `--config` 接入上游 `runAuthenticationValidation`。验证失败终止工作流，不降级成匿名扫描；通过后共享该任务的浏览器 storage state 给后续 Agent。当前仅同源表单登录；邮箱验证码现支持下节的人工输入；跨域企业 SSO、短信验证码、扫码、CAPTCHA 与多角色账号切换尚未接入。任务列表及详情仅返回 `authenticated_scan`，不提供凭据读取接口。

凭据单独使用 AES-256-GCM 加密保存到任务目录 `authentication.enc`，密钥在实例数据卷 `.target-credentials-key`（0600），不会写入 SQLite、镜像、命令参数或环境变量。使用镜像中已有 Node crypto，无新增第三方运行依赖。队列任务重启后仍可读取加密凭据；密文被篡改或密钥丢失时拒绝执行。备份与恢复必须包含匹配密钥；同卷密钥不防护取得整个实例数据卷权限的管理员。

运行时私有 `login-config.json` 为 0600，通过文件路径传入 Worker，Temporal 输入只记录路径。确认工作流终止后清理该配置及 `auth-state.json`；中断任务先清理持久工作流再删文件。运行中的模型和浏览器必然需要读取凭据，模型网关会收到相关提示；上游内部审计轨迹及浏览器工具产物也可能含会话/凭据，属于私有敏感数据，不能公开或将整个任务目录作为报告下载。卷、备份与运维访问应按测试凭据敏感级别管理。

Worker 标准输出、API 进度/错误/终态中的已知账号、密码、TOTP 原值及常见编码进行替换。报告提示要求使用占位符，下载 Markdown 时再次脱敏；不能保证模型改写、动态验证码或新产生的 Cookie 全被字符串替换识别，分享报告前仍应检查。登录任务暂不开放原始 PDF 下载，避免二进制报告绕过脱敏；匿名任务原有 PDF 下载保留。后续需在统一脱敏内容上重新生成 PDF。

登录功能沿用所选执行模式与可选的目标限制；当前根声明默认开发内测，严格模式仍保留外部 CNI 确认要求。填写账号不会增加其他域名的授权范围。真实扫描前需使用已授权测试环境及测试账号完成登录成功、密码错误、TOTP、目标越权拦截验收。新增 5 项测试覆盖范围校验、凭据加密/重启/篡改拒绝、API 不返回凭据及报告脱敏、Worker 配置传递和清理、控制台脱敏；共 18 项 Python 测试。本次自动化使用夹具数据，不调用真实模型、不扫描真实网站。


## 人工邮箱验证码（2026-11-08）

创建任务时在被测网站登录设置勾选“登录需要邮箱验证码（人工输入）”，无需提供邮箱密码。保留账号密码及成功条件；登录步骤可写明“提交账号密码、等待人工邮箱验证码、填写后完成验证”。人工邮箱验证与 TOTP 二选一，不将动态验证码写进静态配置。

登录验证 Agent 等网站发送邮件并出现验证码输入框后，调用仅注册在该阶段的 `request_email_code` 工具。每轮验证码输入最多 5 分钟，允许在同一任务中纠正或主动重发，最多 3 轮、总等待不超过 8 分钟；任务显示 `waiting_for_code`。用户在任务详情填写 4–12 位字母或数字，调用 `POST /api/v1/tasks/{id}/email-code`，请求为 `{ "request_id": "当前挑战 id", "code": "本次验证码" }`，响应只返回 `accepted`。接口沿用 4YI SSO、组织及 Origin 校验，校验任务状态、挑战 id、有效期和是否已提交。定时刷新保留正在输入的内容和焦点；提交后清空输入框，继续同一浏览器会话。

任务记录及 API 不包含验证码。每任务挑战只保存随机 id、截止时间和提交标记；响应使用现有实例 AES-256-GCM 密钥加密落盘，校验挑战 id 后消费，随后删除等待请求和响应文件。加密的 OTP 脱敏材料单独保留，供后续 Markdown 下载与日志替换使用。验证码不写入 SQLite 或浏览器 localStorage。登录 Agent 为填写浏览器必须接收验证码，所以模型上下文、上游私有审计轨迹和目标网站浏览器产物仍可能含该值，不能公开整个任务目录；不承诺所有内部审计文件都无验证码。

总等待超时、取消、篡改、跨任务响应与旧挑战重复使用均拒绝继续该次等待。登录验证活动不自动重试，避免重新发送邮件或重复提交账号密码。没有收到人工验证码时，即使模型声称成功也拒绝通过；收到后仍须按原流程验证网站登录成功并保存浏览器状态。取消或重启后的中断任务按原机制先终止 Temporal 工作流再清理等待文件和浏览器会话，不自动重登或恢复过期验证码；总时限/轮次耗尽、浏览器会话失效或账号锁定后才需要新建任务。邮件实际有效期可能短于 5 分钟，重发始终需要用户主动请求。

验证包含 20 项 Python 测试（含等待超时实际终止 Worker 进程）、Node 实际等待工具的成功/超时/取消/重放/篡改夹具，以及本机浏览器的等待、刷新保留输入及焦点、提交继续、取消和桌面/手机布局。使用模拟账号、验证码及本机 IPC，不调用真实模型、邮箱服务或扫描目标；真实邮件送达、目标页面识别与登录后扫描仍需授权环境验收。执行模式以本文当前开发内测说明为准，PIAQEE 后续待办不变，不修改平台代码。


## 邮箱验证码纠正与重新发送（2026-11-08）

在同一浏览器登录会话中，网站明确拒绝验证码但仍保留验证码表单时，登录 Agent 用 `reason=incorrect` 再次调用等待工具，任务详情显示“网站未接受上次验证码，请重新输入”，无需重新上传代码或创建任务。每个新挑战有独立随机 id，上一轮的提交不能用于下一轮。最多 3 轮（包括首次、纠错及重发后的等待），每轮输入最多 5 分钟；所有轮次共用首次开始计算的 8 分钟总时限，不会因重新输入而无限延长。

任务详情新增“请求重新发送验证码”，调用 `POST /api/v1/tasks/{id}/email-resend`，正文仅 `{ "request_id": "当前挑战 id" }`。按钮与接口均检查 60 秒冷却和剩余轮次。已过本轮输入时限但仍在总时限内，可请求重发；最后一轮不能再重发。服务器只接受请求，不声称邮件已经送达。等待工具消费加密的重发指令后，告知登录 Agent 在当前网站会话中点击一次重发控件；只有网站确认发送后，才用 `reason=after_resend` 发布下一轮输入。网站无重发功能、拒绝发送、要求重新登录或账号被锁时停止，不尝试绕过，也不重新提交账号密码。

同一任务的所有已提交验证码都保留在加密的脱敏材料列表中，后续控制台/API 错误及 Markdown 下载继续替换旧码和新码，不会因下一轮覆盖而丢失旧码脱敏。兼容上一版单验证码加密材料。工具同时只允许一个活动等待，总时限耗尽会终止 Worker；真实网站的错误识别和重发操作依赖登录 Agent 的页面判断，仍须授权目标验收。本轮测试包含 22 项 Python 回归（含轮次间隙总时限，以及登录验证成功后不误杀后续扫描）、Node 的连续纠正/主动重发/共用截止时间/并发拒绝/次数上限，以及浏览器同一任务错误码重输、重发后继续和手机布局夹具。


## 安装后默认可创建扫描（2026-11-08）

与 Trivy、PentAGI 的安装后使用方式对齐，但不复制其固定数据库凭据。开发内测模式去掉每目标手工白名单及出口验收标记的门槛，仍保留 4YI SSO、请求同源、授权勾选、地址检查、源码检查、任务持久化、登录与人工验证码流程。资源和三服务结构不变。根声明中启用开关和模式是公开非敏感配置；模型与数据库凭据仍按实例注入。

升级已有安装时重新 Analyze/Apply 最新源码并创建/更新到对应 Release，确认实际消费者 Web 服务采用 `SHANNON_EXECUTION_ENABLED=true`、`SHANNON_EXECUTION_MODE=trusted_dev`；不是只更新 Git 仓库或刷新旧 Release。应用 `/shannon-healthz` 和登录后 `/api/v1/config` 都返回执行模式/开关；前端显示“开发内测”及页面提交目标的策略，按钮跟随后端真实开关，不会仅在 UI 解禁。

本轮 25 项 Python 回归包含直接读取根声明启动 HTTP 服务、缺少人工策略变量仍可创建排队任务、未登录拒绝、可选目标限制、两个不同公网目标接收、私网/元数据拒绝、严格模式仍需确认、显式关闭/未知模式保持关闭。Chrome/Playwright 使用本机模拟 SSO、源码和目标验证按钮、ZIP 提交、取消、错误提示及桌面/390px 手机布局。测试执行循环由夹具替换，不访问真实目标或模型；三服务 smoke 显式关闭执行，避免将默认开启扩散到自动化扫描。
