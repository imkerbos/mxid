# 部署

本文讲生产环境部署。开发快速开始见 [README](../README_ZH.md#快速开始开发环境)。

[English](DEPLOYMENT.md) · **简体中文**

## 拓扑

MXID 采用**单域名 + 路径前缀**路由模型 —— 与 Keycloak / GitLab / Nextcloud 一致:

```
https://<host>/                       → 门户 SPA            (终端用户登录 + 我的应用)
https://<host>/admin/                 → 控制台 SPA          (管理)
https://<host>/api/v1/console/...     → 后端 REST           (管理鉴权)
https://<host>/api/v1/portal/...      → 后端 REST           (终端用户鉴权)
https://<host>/api/v1/portal-public/  → 后端 REST           (免登:密码重置/魔法链接/短信)
https://<host>/api/v1/openapi/...     → 后端 REST           (API token 鉴权)
https://<host>/api/v1/system/...      → 后端 REST           (公开 bootstrap / info)
https://<host>/protocol/oidc/...      → OIDC IdP
https://<host>/protocol/saml/...      → SAML IdP
https://<host>/protocol/cas/...       → CAS IdP
https://<host>/static/...             → 后端静态
https://<host>/health                 → 存活探针
```

dev(`http://localhost:3500/...`)和 prod(`https://id.example.com/...`)只差 host。集成文档、OIDC `redirect_uri` 白名单、CAS service URL 都按这套路径。

### 双 Pod 运行时

```
                    ┌─────────────────────────────────┐
                    │  mxid-nginx pod                 │
   外部流量         │  ├─ TLS 终止                   │
   ───────────────► │  ├─ /admin/* → console dist    │  (卷 / 烤入镜像)
                    │  ├─ /*       → portal  dist    │
                    │  └─ /api/*, /protocol/*,       │
                    │     /static/*, /health         │
                    │            ▼ 反向代理          │
                    └────────────│────────────────────┘
                                 ▼
                    ┌─────────────────────────────────┐
                    │  mxid-backend pod (Go 二进制)   │
                    │  无静态文件 — 纯 REST           │
                    └─────────────────────────────────┘
                                 │
                  ┌──────────────┼──────────────┐
                  ▼              ▼              ▼
              PostgreSQL       Redis        SMTP/SMS
```

nginx pod 持有 SPA 静态(烤进 `mxid-web` 镜像);后端 pod 是无状态 Go 二进制。两者**独立**部署、扩缩、升级。外部 URL 在**控制台 → 设置 → 外部 URL** 运行时可改,无需重启。

## 需求

| 组件 | 版本 | 说明 |
|------|------|------|
| Go | 1.25+ | 构建二进制,运行时不需要 |
| Node | 22+ | 构建 SPA,运行时不需要 |
| PostgreSQL | 15+ | 主数据存储。扩展 `pg_trgm`(迁移 0030 自动装) |
| Redis | 7+ | 会话/票据/TOTP 限流/事件 SSE。建议开 AOF 或 RDB 持久化 |
| SMTP | 任意 | 可选。无 SMTP 时密码重置/魔法链接邮件回退为 API 响应里的 `dev_link` |

## 配置

配置解析优先级(高 → 低):

1. `MXID_` 前缀环境变量(如 `MXID_SERVER_PORT`)
2. `configs/config.prod.yaml`(当 `MXID_CONFIG_ENV=prod`)
3. `configs/config.yaml`(默认值)

`.env.example` 列出所有支持的变量。

### 必需密钥

`release` 模式下,这些没设成真实值(拒绝 dev 占位)后端拒绝启动;compose 缺任一则中止。

| 变量 | 用途 | 生成 |
|------|------|------|
| `MXID_CRYPTO_KEY_ENCRYPTION_KEY` | 主 KEK —— AES 加密 OIDC 签名密钥 + 敏感设置(SMTP/SMS 密钥、OAuth client secret)。**每部署唯一;轮换会使已有应用签名密钥失效。** | `openssl rand -base64 32` |
| `MXID_CRYPTO_AUDIT_CHAIN_KEY` | 防篡改审计哈希链的 HMAC 密钥。**只生成一次、永不更改 —— 轮换会使所有已有审计条目验证失败**(与 KEK 同级稳定性要求)。 | `openssl rand -base64 32` |
| `MXID_CRYPTO_AUDIT_ANCHOR_KEY` | 签名外部 Merkle 锚的 Ed25519 seed。`audit.anchorSink.enabled`(默认开)时必填。若要轮换,须把旧公钥保留在 `crypto.audit_anchor_retired_pubkeys` 里,否则旧锚验不过。 | `openssl rand -base64 32` |
| `POSTGRES_PASSWORD`(→ `MXID_DATABASE_PASSWORD`) | PostgreSQL 密码 | 强随机 |
| `REDIS_PASSWORD`(→ `MXID_REDIS_PASSWORD`) | Redis 密码 | 强随机 |

`release` 模式还要求 `session.cookie_secure: true`(HTTPS)。OIDC 令牌签名密钥由 app 生成并加密(KEK)存储 —— 无需密钥环境变量。

### 环境变量参考(`.env`)

部署所需全在 `.env`(从 `.env.example` 拷)。生产完整集:

| 变量 | 必需 | 默认 | 用途 |
|------|:--:|------|------|
| `COMPOSE_FILE` | ✅ | — | 加载哪些 compose 文件 = 部署模式。见下文 |
| `MXID_TAG` | ✅ | — | 钉的镜像版本(如 `v0.1.0`)。无 `latest` |
| `MXID_CRYPTO_KEY_ENCRYPTION_KEY` | ✅ | — | 主 KEK(`openssl rand -base64 32`) |
| `POSTGRES_PASSWORD` | ✅ | — | DB 密码 |
| `REDIS_PASSWORD` | ✅ | — | Redis 密码 |
| `MXID_SERVER_ALLOWED_ORIGINS` | ✅ | — | CORS/CSRF 白名单,逗号分隔(如 `https://id.example.com`)。启动时定 |
| `SERVER_NAME` | ✅ | `_` | nginx TLS `server_name`(你的域名) |
| `CERT_FILE` | ✅ | `server.crt` | `deploy/compose/cert/` 下证书文件名 |
| `KEY_FILE` | ✅ | `server.key` | `deploy/compose/cert/` 下私钥文件名 |
| `POSTGRES_USER` / `POSTGRES_DB` | — | `postgres` / `mxid` | DB 用户 / 库名 |
| `MXID_DATABASE_HOST` | — | `host.docker.internal`(standalone:`postgres`) | 外部 DB host(仅外部DB模式) |
| `MXID_DATABASE_PORT` / `MXID_REDIS_PORT` | — | `5432` / `6379` | DB / Redis 端口 |
| `MXID_REDIS_HOST` | — | `host.docker.internal`(standalone:`redis`) | 外部 Redis host |

> 域名 / issuer / portal / console URL **不是** env —— 首次登录后在控制台(设置 → 外部 URL)设,热生效。唯一例外是 `MXID_SERVER_ALLOWED_ORIGINS`,必须启动时已知。License 也**不是** env —— 在控制台激活(存 DB)。

## 容器镜像与版本

GHCR 镜像 —— 生产全容器化(无宿主构建、无 `dist/` 挂载):

```
ghcr.io/imkerbos/mxid       # CE 后端(公开)
ghcr.io/imkerbos/mxid-web   # nginx + 两个 SPA 烤入(CE/EE 共用)
ghcr.io/imkerbos/mxid-ee    # EE 后端(私有,garble 混淆)— 见 EDITIONS
```

tag 驱动发布。推 SemVer git tag(`vMAJOR.MINOR.PATCH`)触发 `.github/workflows/release.yml`,多架构构建并推标准 tag 集 + 建 GitHub Release。main / PR 不构建 —— CI 只用于发布。

| Tag | 漂移? | 用途 |
|-----|------|------|
| `v1.2.3` | 永不(不可变) | **生产钉这个** |
| `v1.2` | 该 minor 最新 patch | 跟补丁 |
| `v1` | 该 major 最新 minor | 跟大版本线 |

**无 `latest`** —— 生产必须钉显式版本(后端启动跑迁移,漂移 tag = 意外迁移)。

同一标识符贯穿:**git tag = 镜像 tag = 二进制版本(`/health`、`/system/info`、控制台版本页)= `.env` 的 `MXID_TAG`**。发版:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

## Docker compose 生产部署

部署只动**一个文件 —— `.env`**。不改 YAML 配置、不改 compose;env 覆盖优先,其余(域名、SMTP、品牌…)首登后在控制台设。

```bash
git clone https://github.com/imkerbos/mxid.git   # 只为拿 compose 文件 + .env + 证书
cd mxid
cp .env.example .env
```

编辑 `.env` 的生产段:

```ini
# 模式:外部 DB(默认)— 或解开第二行用自包含栈(容器 Postgres + Redis + 卷)
COMPOSE_FILE=deploy/compose/docker-compose.yml
# COMPOSE_FILE=deploy/compose/docker-compose.yml:deploy/compose/docker-compose.standalone.yml

MXID_TAG=v1.0.0                                      # 必需 — 钉一个发布版
MXID_SERVER_ALLOWED_ORIGINS=https://id.example.com   # CORS/CSRF 白名单(启动时定)
SERVER_NAME=id.example.com
CERT_FILE=fullchain.pem
KEY_FILE=privkey.pem
# 密钥:POSTGRES_PASSWORD / REDIS_PASSWORD / MXID_CRYPTO_KEY_ENCRYPTION_KEY
```

把 TLS 证书 + 私钥放 `deploy/compose/cert/`(文件名对应 `CERT_FILE` / `KEY_FILE`),然后:

```bash
make prod-docker-up           # 等价于:docker compose up -d
```

完事 —— compose 读 `.env` 的 `COMPOSE_FILE`,拉匹配的后端 + web 镜像并启动。

> **Standalone 模式**(Postgres + Redis 打包进 compose,无外部依赖):解开第二条 `COMPOSE_FILE`。适合单机试用;生产建议用托管 Postgres / Redis(见 Kubernetes 章节)。

两种**部署模式**通过 `COMPOSE_FILE` 切换:

| 模式 | `COMPOSE_FILE` 值 | 适用场景 |
|------|-------------------|---------|
| **外部 DB**(默认) | `docker-compose.yml` | 托管 Postgres + Redis(RDS、CloudSQL、ElastiCache…) |
| **Standalone** | `docker-compose.yml:docker-compose.standalone.yml` | 自包含 — Postgres + Redis 内置 |

> **容器名隔离**:dev compose 的 nginx 容器名为 `mxid-nginx-dev`,prod 为 `mxid-nginx`。同一宿主机同时跑 dev 和 prod 时名称不冲突,两栈均可正常启动。

**为什么只配这几个 env?** `MXID_SERVER_ALLOWED_ORIGINS` 是 CORS/CSRF 白名单,必须启动时已知(它决定谁能访问控制台去改其它设置)。其余 URL(issuer/portal/console)在**控制台**(设置 → 外部 URL)设、热生效;YAML 只是兜底。

### TLS 证书

证书由运维提供,从 `deploy/compose/cert/` 只读挂进 web 容器 —— 绝不烤进镜像。web 镜像 nginx 跑 `80`(跳 443)和 `443`;`.env` 的 `SERVER_NAME` / `CERT_FILE` / `KEY_FILE` 启动时替换进 nginx 配置。

```bash
mkdir -p deploy/compose/cert
# 把证书 + 私钥放这里,文件名对应 .env 的 CERT_FILE / KEY_FILE
deploy/compose/cert/
├── fullchain.pem      # CERT_FILE — 全链(叶 + 中间证书)
└── privkey.pem        # KEY_FILE  — 私钥
```

**正式证书(Let's Encrypt / CA 签发)**:用全链作 `CERT_FILE`。Let's Encrypt 的 `fullchain.pem` + `privkey.pem` 1:1 对应,拷进来即可(或软链/续期 hook 指向此目录)。compose 还挂了 `./acme` 作 HTTP-01 续期 webroot(可选)。

**自签(仅测试)**:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout deploy/compose/cert/privkey.pem \
  -out   deploy/compose/cert/fullchain.pem \
  -subj  "/CN=id.example.com"
```

**已有 ingress**(Traefik / Caddy / ALB)? 在那终止 TLS,转发明文 HTTP 给 web 容器 —— 去掉证书挂载和 `prod.conf` 的 `listen 443 ssl` 块。

> `deploy/compose/cert/` 已 gitignore —— 私钥不会被提交。

### 社区版 vs 企业版

上面跑的是**社区版**。**企业版**:在 `COMPOSE_FILE` 链上 EE 叠加文件(把后端换成私有 `mxid-ee` 镜像)+ 激活 license。详见 [EDITIONS](EDITIONS.md);部署差异:

```ini
# .env — 加 EE 叠加
COMPOSE_FILE=deploy/compose/docker-compose.yml:deploy/compose/docker-compose.ee.yml
```

```bash
docker login ghcr.io       # mxid-ee 私有 — token 需 read:packages
docker compose pull
docker compose up -d
```

License 在控制台激活(设置 → 许可信息);存 DB 并热重载,换镜像/重启都保留 —— 无 env。无 license → CE;过期 → CE 上限,已有数据 grandfather。

## Kubernetes 部署

> 本章节假设你熟悉 Kubernetes。Docker compose 路径更简单且完整受支持 —— 只有在需要滚动更新、水平扩展或集群原生可观测性时才选 Kubernetes。

### 为什么 MXID 适合 Kubernetes

后端**完全无状态** —— 图标上传存数据库(无本地文件系统状态),前端 SPA 已烤进 `mxid-web` 镜像由 nginx 提供。应用本身**不需要 PVC**,也不存在 `ReadWriteOnce` 多挂死锁风险。需要持久化的只有外部状态(PostgreSQL、Redis)。

### 组件映射

| 角色 | Kubernetes 资源 | 说明 |
|------|----------------|------|
| 后端(`mxid` / `mxid-ee`) | `Deployment`(MVP)或 `StatefulSet`(多副本) | 见下文 *nodeID* |
| 前端(`mxid-web`) | `Deployment` | 无状态 nginx,副本数不限 |
| PostgreSQL | 外部托管(RDS、CloudSQL)或 operator(如 CloudNativePG) | 生产不要裸 `Deployment` 跑 PG |
| Redis | 外部托管(ElastiCache、MemoryStore)或 operator | |
| TLS 入口 | `Ingress` + cert-manager | 或云 LB 托管证书 |
| DB schema 迁移 | Helm `pre-upgrade` / `pre-install` `Job` | 见下文 *迁移* |

### nodeID 唯一性约束

每个后端副本必须有**唯一的 Snowflake `node_id`**(10-bit,0–1023)。重复的 node_id 在并发负载下会导致主键冲突。

**方案 A —— StatefulSet ordinal(推荐,零代码)**:使用 `StatefulSet`(无需 `volumeClaimTemplates`,后端不需要 PVC),将 pod 序号传为 node_id:

```yaml
# StatefulSet pod template
env:
  - name: POD_ORDINAL
    valueFrom:
      fieldRef:
        fieldPath: metadata.annotations['apps.kubernetes.io/pod-index']
  - name: MXID_SNOWFLAKE_NODE_ID
    value: "$(POD_ORDINAL)"
```

副本 0 → `node_id=0`,副本 1 → `node_id=1`,以此类推。最多安全扩展到 1023 副本。

**方案 B —— Redis 启动租约**:每个 pod 启动时从 Redis hash-set 抢占最小空闲 node_id。适用于普通 `Deployment`,但需要在生成第一个 Snowflake ID 前连通 Redis。

**单副本 MVP**:固定任意值(如 `MXID_SNOWFLAKE_NODE_ID=0`)即可,无冲突风险。

### License 指纹与 PostgreSQL `system_identifier`

EE license 指纹 = `HMAC(install_uuid | PostgreSQL system_identifier)`。因为所有后端副本连的是**同一数据库**,它们计算出完全相同的指纹 —— 无需逐副本重新激活。

**重要**:`system_identifier` 在物理复制和故障转移(如 Patroni / CloudNativePG switchover)中保持不变。但**逻辑恢复**(`pg_dump` → `pg_restore` 到新集群)会生成新的 `system_identifier`,导致指纹失效。逻辑恢复到新集群后,需在控制台重新激活 license(设置 → 许可信息)。

### 数据库迁移

迁移在后端启动时自动跑,使用 golang-migrate + postgres driver 的**advisory lock** —— 并发 pod 不会重复执行迁移。如果你倾向于在 GitOps / Helm 工作流中显式控制,可将迁移作为 `pre-upgrade` Helm hook Job 在滚动更新前执行:

```yaml
# helm/templates/migration-job.yaml(节选)
annotations:
  "helm.sh/hook": pre-upgrade,pre-install
  "helm.sh/hook-weight": "-5"
  "helm.sh/hook-delete-policy": before-hook-creation
spec:
  template:
    spec:
      containers:
        - name: migrate
          image: ghcr.io/imkerbos/mxid:{{ .Values.image.tag }}
          command: ["/app/mxid", "migrate", "up"]
```

无论哪种方式 —— 自动或 Job —— advisory lock 均能保证安全。

### 健康检查

`/health` 端点同时用于 liveness 和 readiness 探针:

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 10050
  initialDelaySeconds: 10
  periodSeconds: 15
readinessProbe:
  httpGet:
    path: /health
    port: 10050
  initialDelaySeconds: 5
  periodSeconds: 10
```

### SSRF 与云 metadata

后端所有对外 HTTP 请求经过 `pkg/safehttp`,已拦截云 metadata 端点(包括 `169.254.169.254`)。应用层无需额外 NetworkPolicy 防 SSRF,但在共享集群中配默认拒绝出口的 `NetworkPolicy` 仍是纵深防御的好实践。

### CE → EE 零停机切换

从社区版切企业版只需一行镜像替换 —— 原理与 Docker compose 改 `COMPOSE_FILE` overlay 完全相同,但实现为滚动更新:

```bash
helm upgrade mxid ./helm/mxid \
  --set image.repository=ghcr.io/imkerbos/mxid-ee \
  --set image.tag=v1.0.0
```

Kubernetes 执行滚动更新:新 EE pod 启动(自动注册 `external_idp` 等 EE 功能),旧 CE pod 终止。数据库中已有的 license 自动生效 —— 无需重新激活。回退:

```bash
helm rollback mxid
```

### 分阶段部署

**MVP(单副本)**

```yaml
kind: Deployment
spec:
  replicas: 1
  strategy:
    type: Recreate        # 避免滚动期间 node_id 重叠
```

使用外部托管 PostgreSQL 和 Redis。无需 PVC。

**生产(多副本,水平扩展)**

```yaml
kind: StatefulSet
spec:
  replicas: 3             # node_id: 0、1、2 来自 pod ordinal
  # 无 volumeClaimTemplates — 后端无状态
```

对 CPU/RPS 指标配 `HorizontalPodAutoscaler`。确保 `PostgreSQL max_connections ≥ database.max_open_conns × 副本数`。

### 使用 Helm chart 部署

仓库内置 Helm chart,路径 `deploy/helm/mxid`。它渲染后端 `StatefulSet`、前端
`Deployment`、各自的 `Service`、`ConfigMap`、`Secret`(可选),以及根据
`routing.type` 选择的单个路由资源(`VirtualService`、`HTTPRoute` 或 `Ingress`)。
**chart 不负责创建 Istio Gateway、Gateway API Gateway 或 cert-manager `Certificate`**
——这些是集群级资源,需提前准备好。

#### 前置条件

- Helm 3.x
- 外部 PostgreSQL 15+ 和 Redis 7+(连接信息填入 values)
- 集群内已安装路由入口(Istio、Gateway API controller 或 Ingress controller)

#### 安装

```bash
helm install mxid deploy/helm/mxid \
  -n mxid --create-namespace \
  -f values-prod.yaml
```

也可用 `--set` 逐项覆盖:

```bash
helm install mxid deploy/helm/mxid \
  -n mxid --create-namespace \
  --set edition=ce \
  --set host=id.example.com \
  --set image.tag=v1.0.0 \
  --set database.host=pg.internal \
  --set redis.host=redis.internal \
  --set secrets.databasePassword=<db-pw> \
  --set secrets.redisPassword=<redis-pw> \
  --set secrets.cryptoKeyEncryptionKey=$(openssl rand -base64 32) \
  --set secrets.auditChainKey=$(openssl rand -base64 32) \
  --set secrets.auditAnchorKey=$(openssl rand -base64 32)
```

#### 最小生产 values 文件

创建 `values-prod.yaml`,只填必填项,其余继承 chart 默认值:

```yaml
# values-prod.yaml — 生产必填最小集
edition: ce               # "ce" (ghcr.io/imkerbos/mxid) 或
                          # "ee" (ghcr.io/imkerbos/mxid-ee)
host: id.example.com      # 对外域名 — 用于路由规则

image:
  tag: "v1.0.0"           # 钉一个发布版,不要用 "latest"

database:
  host: "pg.prod.internal"
  port: "5432"
  name: "mxid"
  user: "mxid"

redis:
  host: "redis.prod.internal"
  port: "6379"

secrets:
  # 生产优先 create: false + existingSecret(见下),让明文密钥不落进本文件。
  # 这里 create: true 仅为示例完整性。
  create: true
  databasePassword: ""            # 必填 — DB 密码
  redisPassword: ""               # 必填 — Redis 密码(无认证则留空)
  cryptoKeyEncryptionKey: ""      # 必填 — openssl rand -base64 32
  auditChainKey: ""               # 必填 — openssl rand -base64 32(永不更改)
  auditAnchorKey: ""              # 必填 — openssl rand -base64 32

routing:
  type: gatewayapi                # gatewayapi(默认)| istio | ingress | none
  gatewayapi:
    name: "mxid-gateway"          # 已存在的 Gateway 名
    namespace: ""                 # Gateway 命名空间(同 ns 留空)
    sectionName: ""               # 可选 listener,如 "https"

backend:
  replicaCount: 2                 # 默认 2(HA);后台单写任务已 leader 选举
```

> **不要把含明文密钥的 `values-prod.yaml` 提交到 git。**
> CI 中改用 `--set` 传参,或用 Sealed Secrets、External Secrets Operator、
> Vault agent 注入。

#### 生产用 `existingSecret`(推荐)

让密钥完全不进 Helm values:自己在集群外建 Secret(经密钥管理系统),chart 只引用。
Secret **必须**含全部 5 个 key:

```bash
kubectl create secret generic mxid-secrets -n mxid \
  --from-literal=MXID_DATABASE_PASSWORD='<db-pw>' \
  --from-literal=MXID_REDIS_PASSWORD='<redis-pw>' \
  --from-literal=MXID_CRYPTO_KEY_ENCRYPTION_KEY='<openssl rand -base64 32>' \
  --from-literal=MXID_CRYPTO_AUDIT_CHAIN_KEY='<openssl rand -base64 32>' \
  --from-literal=MXID_CRYPTO_AUDIT_ANCHOR_KEY='<openssl rand -base64 32>'
```

```yaml
# values-prod.yaml
secrets:
  create: false
  existingSecret: mxid-secrets
```

优先 External Secrets Operator(从 Vault / AWS Secrets Manager / GCP SM 拉)或
Sealed Secrets,而非手动 `kubectl create secret`。`create: false` 时 chart
不校验这些 key —— app boot 时仍会 fail-closed(缺任一即起不来)。**且
`helm uninstall` 不会删这个自建 Secret(它不归 Helm 管),KEK / 审计链密钥不会
被误删。**

#### 关键 values 说明

| 键 | 默认值 | 说明 |
|----|--------|------|
| `edition` | `ce` | `ce` → 后端镜像 `ghcr.io/imkerbos/mxid`;`ee` → `ghcr.io/imkerbos/mxid-ee` |
| `host` | `id.example.com` | 对外域名,用于所有路由资源 |
| `image.tag` | `1.0.0` | 后端与前端共用的镜像 tag(钉发布版) |
| `image.pullPolicy` | `IfNotPresent` | 镜像拉取策略 |
| `imagePullSecrets` | `[]` | 私有仓库拉取 Secret 名列表(`edition: ee` 时需要) |
| `backend.replicaCount` | `2` | 后端副本数(默认 2,HA);每个 pod 从序号派生唯一 Snowflake nodeID。单写后台任务已 leader 选举,>1 安全 |
| `backend.autoscaling.enabled` | `false` | 开启对后端 StatefulSet 的 HPA |
| `backend.autoscaling.minReplicas` | `1` | HPA 最小副本数 |
| `backend.autoscaling.maxReplicas` | `5` | HPA 最大副本数 |
| `database.host` | `postgres` | PostgreSQL 主机名 |
| `database.port` | `5432` | PostgreSQL 端口 |
| `database.name` | `mxid` | 数据库名 |
| `database.user` | `mxid` | 数据库用户 |
| `redis.host` | `redis` | Redis 主机名 |
| `redis.port` | `6379` | Redis 端口 |
| `secrets.create` | `true` | 从 values 创建 Secret;设 `false` 时改用 `secrets.existingSecret` 引用已有 Secret |
| `secrets.keepOnUninstall` | `true` | `create: true` 时给 Secret 加 `helm.sh/resource-policy: keep`,`helm uninstall` 不删它(保护 KEK + 审计链密钥)。被保留的 Secret 仍带 Helm ownership 元数据,同名同 ns 重装会直接接管(不报 already exists) |
| `secrets.preserveExisting` | `true` | `create: true` 时让 Secret 幂等:若已存在则复用其现有各 key 值,不用 values 覆盖。重装/升级(含 uninstall 保留后)绝不覆盖已有 KEK / 审计链密钥。设 `false` 则强制用 values(如主动轮换密码) |
| `secrets.existingSecret` | `""` | 已有 Secret 名(需包含 `MXID_DATABASE_PASSWORD`、`MXID_REDIS_PASSWORD`、`MXID_CRYPTO_KEY_ENCRYPTION_KEY`、`MXID_CRYPTO_AUDIT_CHAIN_KEY`、`MXID_CRYPTO_AUDIT_ANCHOR_KEY`) |
| `secrets.databasePassword` | `""` | DB 密码(`secrets.create: true` 时使用) |
| `secrets.redisPassword` | `""` | Redis 密码(无认证则留空) |
| `secrets.cryptoKeyEncryptionKey` | `""` | 主 KEK — `openssl rand -base64 32` |
| `secrets.auditChainKey` | `""` | 审计哈希链 HMAC 密钥 — `openssl rand -base64 32`;**只生成一次、永不更改** |
| `secrets.auditAnchorKey` | `""` | 审计锚 Ed25519 seed — `openssl rand -base64 32`;`audit.anchorSink.enabled` 时必填 |
| `audit.anchorSink.enabled` | `true` | 把签名的外部审计锚持久化到 per-pod PVC(StatefulSet `volumeClaimTemplates`) |
| `routing.type` | `gatewayapi` | 路由后端:`gatewayapi`(默认)、`istio`、`ingress` 或 `none` |
| `config.serverMode` | `release` | `release` 或 `debug` |
| `config.allowedOrigins` | `""` | CORS 白名单;留空则默认 `https://<host>` |

#### 入口路由三选一

chart 根据 `routing.type` 渲染唯一一个路由资源。**chart 不负责创建
Gateway 或 Ingress controller**,需引用集群中已有的资源。

**Istio — VirtualService(默认)**

chart 渲染 `VirtualService`,按路径分流:
`/api`、`/protocol`、`/static`、`/health` 转发到后端 `Service`,其余转到前端
`Service`。引用已有 `Gateway`:

```yaml
routing:
  type: istio
  istio:
    gateway: "istio-system/mxid-gateway"   # 已有 Gateway 的 namespace/name
```

**Kubernetes Gateway API — HTTPRoute**

```yaml
routing:
  type: gatewayapi
  gatewayapi:
    name: "mxid-gateway"
    namespace: "istio-system"   # 已有 Gateway 资源所在命名空间
    sectionName: ""             # 可选 — 指定 Gateway 的特定监听器
```

**标准 Ingress**

```yaml
routing:
  type: ingress
  ingress:
    className: "nginx"
    annotations:
      nginx.ingress.kubernetes.io/proxy-body-size: "10m"
    tls:
      enabled: true
      secretName: "mxid-tls"   # cert-manager 或手动创建的 Secret
```

#### CE → EE 零停机切换

一行 `helm upgrade` 切换版本。chart 替换后端镜像,Kubernetes 执行滚动更新
——新 EE pod 启动后旧 CE pod 才终止:

```bash
helm upgrade mxid deploy/helm/mxid --reuse-values --set edition=ee
```

数据库中已存的 license 自动生效,无需重新激活。代码分离的 EE 功能
(`external_idp`、`webauthn`、`scim` 等)在启动时自动注册。回退:

```bash
helm rollback mxid
```

#### StatefulSet 与 Snowflake nodeID

后端部署为 `StatefulSet`。每个 pod 的 Snowflake nodeID 由 pod 序号自动派生
(pod-0 → nodeID 0,pod-1 → nodeID 1,……),无需额外协调即可保证副本间唯一性。
chart **无 `volumeClaimTemplates`** —— 后端无本地状态(图标存数据库)。
水平扩展只需调大 `backend.replicaCount` 或开启 `backend.autoscaling`。

#### TLS / HTTPS 配置

TLS 终止方式取决于所选的路由模式。

**Ingress 模式**

设置 `routing.ingress.tls.enabled=true` 并在 `routing.ingress.tls.secretName`
填入 Kubernetes TLS Secret 的名称。Secret 有两种来源:

**(a) cert-manager(推荐)** —— 在 `routing.ingress.annotations` 加入
cluster-issuer 注解,cert-manager 将自动创建并续期该 Secret:

```yaml
routing:
  type: ingress
  ingress:
    className: "nginx"
    annotations:
      cert-manager.io/cluster-issuer: letsencrypt-prod
    tls:
      enabled: true
      secretName: "mxid-tls"   # cert-manager 自动创建并续期此 Secret
```

**(b) 手动** —— 在安装 chart 前手动创建 Secret,再用相同的 `secretName` 引用:

```bash
kubectl create secret tls mxid-tls \
  --cert=fullchain.pem \
  --key=privkey.pem \
  -n mxid
```

**Istio 模式 / Gateway API 模式**

chart **不负责创建 Gateway**。TLS 在**你现有 Gateway 的 listener** 上终止 ——
chart 渲染的 `VirtualService`(Istio)或 `HTTPRoute`(Gateway API)只负责
L7 HTTP 路由。HTTPS 完全由你的 Gateway 配置:

- *Istio*:在对应 `Gateway` 的 listener 上配置 `tls` 段。
- *Gateway API*:在 `Gateway` 资源的 `listeners[].tls` 上配置。

这两种模式下,chart 侧无需也不应重复配置 TLS。

#### 优雅退出(滚动更新/缩容/HPA 缩容时零丢请求)

后端与前端(nginx)pod 均配置了 `preStop` hook 和 `terminationGracePeriodSeconds`,
以避免 pod 终止时丢失正在处理的请求。

**原理**。Kubernetes 终止 pod 时,会同时向 pod 发送 `SIGTERM` 并开始将其从
Service endpoint 中摘除。由于 endpoint 变更通过 kube-proxy 和 mesh 传播需要
几秒,摘除完成前仍可能有新请求被路由到即将关闭的 pod。`preStop` hook 在
`SIGTERM` 发送**之前**先 sleep 若干秒,让数据面完成 endpoint 摘除传播;hook
结束后后端才收到 `SIGTERM`,再用约 10 秒 drain 尚在处理的请求后退出。

**控制该行为的 values:**

| 值 | 默认 | 说明 |
|----|------|------|
| `backend.preStopSleep` | `5` | 后端 pod `preStop` 中 sleep 的秒数,之后才触发 `SIGTERM`。设为 `0` 可关闭该 hook。 |
| `backend.terminationGracePeriodSeconds` | `40` | 必须大于 `preStopSleep + 10`,留出后端 drain 时间。 |
| `web.preStopSleep` | `5` | nginx pod 的同名 hook。设为 `0` 可关闭。 |
| `web.terminationGracePeriodSeconds` | `30` | nginx pod 的优雅退出时限。 |

示例 —— 高流量环境适当延长 sleep:

```yaml
backend:
  preStopSleep: 10
  terminationGracePeriodSeconds: 60   # > preStopSleep (10) + drain 时间 (10)

web:
  preStopSleep: 10
  terminationGracePeriodSeconds: 45
```

## 反向代理头

MXID 仅在配置后才信任 `X-Forwarded-For` + `X-Forwarded-Proto`:

```yaml
server:
  trusted_proxies:
    - 127.0.0.1
    - 10.0.0.0/8
```

代理若不加这些头,`trusted_proxies` 留空,MXID 把代理 IP 当客户端 IP。

## 生产检查清单

- [ ] 全程 HTTPS。设 `server.cookie_secure: true`。
- [ ] 门户 + 控制台在同父域子域时,设 `server.cookie_domain`。
- [ ] `MXID_CRYPTO_KEY_ENCRYPTION_KEY` + DB/Redis 密码强、唯一、私密(非 dev 占位)。
- [ ] PostgreSQL `max_connections` ≥ Go `database.max_open_conns` × 副本数。
- [ ] Redis 持久化(AOF `everysec` 或合适间隔的 RDB)。
- [ ] 配 DB 备份(`pg_dump` / WAL 归档)。
- [ ] **控制台 → 设置 → 外部 URL** 设为规范 https URL。
- [ ] **控制台 → 设置 → SMTP** 配好且测试邮件成功。
- [ ] **控制台 → 设置 → 安全策略** 复核(最小长度、历史、锁定、验证码阈值)。
- [ ] **控制台 → 设置 → 审计策略** 有合理 `retention_days` +(可选)`alert_webhook_url`。
- [ ] 首登管理员密码已改。MFA 已绑。
- [ ] 应用访问策略已设(除非有意,否则没有应用是 `allow public`)。
- [ ] 在反代后则设了 `trusted_proxies`。
- [ ] **(Kubernetes)** 每个后端副本有唯一 `MXID_SNOWFLAKE_NODE_ID`(用 StatefulSet ordinal 或 Redis 租约)。
- [ ] **(Kubernetes)** liveness + readiness 探针指向 `/health`。
- [ ] **(Kubernetes)** 逻辑恢复 PostgreSQL(`pg_dump` → 新集群)后,需在控制台重新激活 EE license —— `system_identifier` 已变。

## 迁移

迁移在后端启动时自动跑。手动:

```bash
make migrate-up                 # 全部应用
make migrate-down               # 回滚最近一条
make migrate-create NAME=foo    # 生成新迁移对
```

生产环境 DB schema **只向前**。down 迁移用于本地 dev / CI 清理。

## 可观测性

- 后端写结构化 JSON 日志到 stdout(`level`、`ts`、`caller`、`msg`)。
- 通过 `X-Request-Id` 头传递请求 ID。
- `/health` 端点用于存活 / 就绪探针(后端就绪时返回 `200 OK`)。
- 审计日志是主要安全信号 —— 查 `mxid_audit_log` 表或接告警 webhook。

## 升级

1. 读 [CHANGELOG.md](../CHANGELOG.md) 看目标版本说明。
2. 备份数据库(`pg_dump`)。
3. 改 `MXID_TAG` 到新版,`docker compose pull && up -d`。迁移启动时自动跑。
4. 验证关键 SP 的集成手册(控制台 `/admin/docs`)仍通过。

## 排错

| 现象 | 可能原因 | 修法 |
|------|---------|------|
| OIDC token `iss` = `http://localhost:10050` | `ExternalURLs.IssuerURL` 空 + `config.IssuerURL` 是 localhost | 在控制台设 `ExternalURLs.IssuerURL` |
| CAS 应用返回 `application not found` | App `code` 不匹配 | `/protocol/cas/<code>/login` 路径段就是 DB `code` 列 |
| 设置保存后看不到 toast "已保存" | monorepo Tailwind `@source` 丢失 | 确认 `web/apps/<app>/src/index.css` 有 `@source "../../../packages/shared/src/**/*.{ts,tsx}"` |
| 门户登录重定向死循环 | cookie 域不匹配 | 设 `server.cookie_domain` 为共享父域 |
