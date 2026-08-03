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
https://<host>/health                 → 存活探针(进程存活)
https://<host>/readyz                 → 就绪探针(ping DB + Redis;未就绪返 503)
https://<host>/metrics               → Prometheus 指标(必须只对内网开放)
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
| `MXID_CRYPTO_AUDIT_CHAIN_KEY` | ✅ | — | 审计哈希链 HMAC 密钥(`openssl rand -base64 32`)。只生成一次、永不更改 |
| `MXID_CRYPTO_AUDIT_ANCHOR_KEY` | ✅* | — | 审计锚 Ed25519 seed(`openssl rand -base64 32`)。审计锚开启(默认)时 release 模式必填 |
| `MXID_CRYPTO_AUDIT_ANCHOR_RETIRED_PUBKEYS` | — | — | 已退役的锚签名 ed25519 公钥(base64,逗号分隔);轮换 `MXID_CRYPTO_AUDIT_ANCHOR_KEY` 时把旧公钥加进来,旧锚才验得过 |
| `MXID_AUDIT_ANCHOR_ENABLED` | — | `true` | 开/关审计锚。设 `false` 是显式退出;否则 release 模式要求锚密钥 |
| `MXID_AUDIT_ANCHOR_SINK_PATH` | — | `data/audit-anchors.log` | 签名审计锚追加写入的文件 |
| `POSTGRES_PASSWORD` | ✅ | — | DB 密码 |
| `REDIS_PASSWORD` | ✅ | — | Redis 密码 |
| `MXID_SERVER_ALLOWED_ORIGINS` | ✅ | — | CORS/CSRF 白名单,逗号分隔(如 `https://id.example.com`)。启动时定 |
| `MXID_SERVER_ISSUER_URL` | ✅ | `https://id.example.com` | 规范 OIDC issuer(`iss`)/ SAML EntityID 基 / CAS 根。必须是真实的外部可达 HTTPS URL —— release 模式拒绝 localhost;第三方会重定向回它 |
| `MXID_SERVER_PORTAL_URL` | ✅ | `https://id.example.com` | 规范门户 URL。单域名部署与 issuer 相同 |
| `MXID_SERVER_CONSOLE_URL` | ✅ | `https://id.example.com/admin` | 规范控制台 URL。单域名部署 = issuer + `/admin` |
| `MXID_SERVER_TRUSTED_PROXIES` | — | — | 受信反代 / LB CIDR(逗号分隔)—— 仅对这些来源从 `X-Forwarded-For` 解析真实客户端 IP。见*反向代理头* |
| `SERVER_NAME` | ✅ | `_` | nginx TLS `server_name`(你的域名) |
| `CERT_FILE` | ✅ | `server.crt` | `deploy/compose/cert/` 下证书文件名 |
| `KEY_FILE` | ✅ | `server.key` | `deploy/compose/cert/` 下私钥文件名 |
| `POSTGRES_USER` / `POSTGRES_DB` | — | `postgres` / `mxid` | DB 用户 / 库名 |
| `POSTGRES_PORT` / `REDIS_PORT` | — | `5432` / `6379` | 宿主机映射的 Postgres / Redis 端口(compose) |
| `MXID_DATABASE_HOST` | — | `host.docker.internal`(standalone:`postgres`) | 外部 DB host(仅外部DB模式) |
| `MXID_DATABASE_NAME` / `MXID_DATABASE_USER` | — | `mxid` / `postgres` | 后端视角的 DB 库名 / 用户 |
| `MXID_DATABASE_PORT` / `MXID_REDIS_PORT` | — | `5432` / `6379` | 后端视角的 DB / Redis 端口 |
| `MXID_REDIS_HOST` | — | `host.docker.internal`(standalone:`redis`) | 外部 Redis host |

> **规范外部 URL(`MXID_SERVER_ISSUER_URL` / `MXID_SERVER_PORTAL_URL` /
> `MXID_SERVER_CONSOLE_URL`)在生产环境必须设为真实 HTTPS URL。**
> 它们是 OIDC issuer(`iss`)、SAML EntityID 基、CAS 根,也是第三方(Lark 及其他
> IdP/SP)重定向回来的地址;release 模式拒绝 localhost。不设的话应用会以
> `id.example.com` 占位符启动。运行时仍可在控制台改(设置 → 外部 URL),但新部署
> 的初始值来自这些 env。License **不是** env —— 在控制台激活(存 DB)。

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

MXID_TAG=v1.8.0                                      # 必需 — 钉一个发布版
MXID_SERVER_ALLOWED_ORIGINS=https://id.example.com   # CORS/CSRF 白名单(启动时定)
MXID_SERVER_ISSUER_URL=https://id.example.com        # 规范 OIDC issuer / SAML EntityID / CAS 根
MXID_SERVER_PORTAL_URL=https://id.example.com        # 规范门户 URL
MXID_SERVER_CONSOLE_URL=https://id.example.com/admin # 规范控制台 URL
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

**为什么配这几个 env?** `MXID_SERVER_ALLOWED_ORIGINS` 是 CORS/CSRF 白名单,必须启动时已知(它决定谁能访问控制台去改其它设置)。规范 URL(`MXID_SERVER_ISSUER_URL` / `MXID_SERVER_PORTAL_URL` / `MXID_SERVER_CONSOLE_URL`)从首次启动起就必须是真实的外部 HTTPS URL —— 它们播种第三方依赖的 OIDC issuer / SAML EntityID / CAS 根。运行时仍可在**控制台**(设置 → 外部 URL)改、热生效;YAML 配置值只是最后兜底。

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
| DB schema 迁移 | 后端启动时自动执行(advisory lock) | 可选:自建 pre-upgrade `Job` —— 见下文 *迁移* |

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

迁移在后端启动时自动跑,使用 golang-migrate + postgres driver 的**advisory lock** —— 并发 pod 不会重复执行迁移,普通滚动更新即安全,无需额外机制。Helm chart **有意不带** pre-upgrade 迁移 Job 模板。

如果你的 GitOps / 变更管理流程仍想显式控制,可自建 `Job`(例如在你的包装 chart 里加 Helm `pre-upgrade` hook),在滚动更新前用后端镜像对数据库先跑一遍;之后各 pod 启动时的迁移因 advisory lock 成为 no-op。无论哪种方式 —— 自动或 Job —— advisory lock 均能保证安全。

### 健康检查

**liveness 用 `/health`**(便宜的"进程是否活着",不查依赖),**readiness 用
`/readyz`** —— `/readyz` 会 ping PostgreSQL 和 Redis,任一不可达即返 `503`,
依赖连接坏掉的 pod 会被摘出 Service 而不是继续吐错。Helm chart 的探针就是
这样接的:

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 10050
  initialDelaySeconds: 10
  periodSeconds: 15
readinessProbe:
  httpGet:
    path: /readyz          # 依赖感知:ping DB + Redis,失败返 503
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
  --set image.tag=v1.8.0
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
  --set image.tag=v1.8.0 \
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
  tag: "v1.8.0"           # 钉一个发布版,不要用 "latest"

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
| `image.registry` | `ghcr.io/imkerbos` | 所有镜像的仓库+命名空间前缀。改它即可指向私有仓库 / Harbor(隔离环境)——需把 `mxid`/`mxid-ee`/`mxid-web`(及 `backend.waitForDeps.image` 的 busybox)镜像到该前缀下,repo 名保持一致 |
| `image.tag` | `v1.8.0` | 后端与前端共用的镜像 tag(钉发布版) |
| `image.backendTag` | `""` | 可选覆盖 —— 独立钉后端镜像(按 `edition` 对应 CE `mxid` 或 EE `mxid-ee`),不跟 `tag`。留空 = 用 `tag` |
| `image.webTag` | `""` | 可选覆盖 —— 独立钉 web 镜像,不跟 `tag`。留空 = 用 `tag` |
| `image.pullPolicy` | `IfNotPresent` | 镜像拉取策略 |
| `imagePullSecrets` | `[]` | 私有仓库拉取 Secret 名列表(`edition: ee` 时需要) |
| `backend.replicaCount` | `2` | 后端副本数(默认 2,HA);每个 pod 从序号派生唯一 Snowflake nodeID。单写后台任务已 leader 选举,>1 安全 |
| `backend.waitForDeps.enabled` | `true` | init 容器:等 Postgres + Redis 能建 TCP 连接后才启动主容器(依赖未起时不 crash-loop) |
| `backend.waitForDeps.image` | `busybox:1.37` | wait-for-deps init 容器镜像(隔离环境记得一并镜像) |
| `backend.autoscaling.enabled` | `false` | 开启对后端 StatefulSet 的 HPA |
| `backend.autoscaling.minReplicas` | `1` | HPA 最小副本数 |
| `backend.autoscaling.maxReplicas` | `5` | HPA 最大副本数 |
| `web.replicaCount` | `2` | web(nginx + SPA)副本数 —— 无状态,任意副本数均安全 |
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
| `routing.forwardedProtoHttps` | `true` | 在后端路由上强制加 `X-Forwarded-Proto: https`(gatewayapi 的 HTTPRoute filter / istio 的 VirtualService header)。**在 TLS 于 Gateway/LB 终止的部署中至关重要:没有这个头,OIDC(zitadel)引擎看到 `scheme=http`,与 https issuer URL 不匹配,discovery/authorize 直接 403。**Ingress controller 通常自己注入该头。只有当你的边缘已转发可信的 `X-Forwarded-Proto` 时才设 `false` |
| `routing.gke.healthCheck.enabled` | `false` | 仅 GKE Gateway API:渲染 `HealthCheckPolicy` 把 Google Cloud LB 健康检查指向 `/health`(LB 默认探 `/` → 404 → 后端被判不健康)。非 GKE 保持关闭(CRD 不存在) |
| `config.serverMode` | `release` | `release` 或 `debug` |
| `config.allowedOrigins` | `""` | CORS 白名单;留空则默认 `https://<host>` |
| `config.trustedProxies` | `[]` | 受信反代 / LB CIDR 列表(渲染为 `MXID_SERVER_TRUSTED_PROXIES`)。设为边缘代理 CIDR,真实客户端 IP 才会从 `X-Forwarded-For` 取;留空回退到宽泛的 RFC1918 默认并在 release 模式告警。见*反向代理头* |
| `config.formFillExtension` | `false` | Form-fill SSO 浏览器扩展(EE `form_fill`):把扩展 origin 加入白名单并把门户 cookie 设为 `SameSite=None`。仅在铺开扩展时才开 |
| `config.issuerUrl` | `""` | 规范 OIDC issuer / SAML EntityID 基 / CAS 根。留空 = 派生为 `https://<host>`;分域部署需显式设置 |
| `config.portalUrl` | `""` | 规范门户 URL。留空 = `https://<host>` |
| `config.consoleUrl` | `""` | 规范控制台 URL。留空 = `https://<host>/admin` |

#### 入口路由三选一

chart 根据 `routing.type` 渲染唯一一个路由资源。**chart 不负责创建
Gateway 或 Ingress controller**,需引用集群中已有的资源。

**Istio — VirtualService**

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

同一配置也可用环境变量 `MXID_SERVER_TRUSTED_PROXIES`(逗号分隔 CIDR),
Kubernetes 上对应 chart 值 `config.trustedProxies`。设为你的边缘代理 / LB
CIDR,应用才会从 `X-Forwarded-For` 解析真实客户端 IP —— 否则所有内网客户端
都塌缩成 LB 的 IP,按客户端的审计、限流、条件访问全部失真。

终止 TLS 的代理**必须向后端转发 `X-Forwarded-Proto: https`** —— OIDC 引擎会
拿请求 scheme 和 https issuer URL 比对,看到裸 `http` 时 discovery/authorize
直接 403(Helm chart 对应 `routing.forwardedProtoHttps: true`,默认开)。

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
- [ ] **(Kubernetes)** liveness 探针 → `/health`;readiness 探针 → `/readyz`(依赖感知)。
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
- 通过 `X-Request-Id` 头传递请求 ID;错误响应带 `traceId` 字段 —— 让用户报
  traceId,再去日志里 grep。
- `/health` —— 存活探针(进程存活,不查依赖)。`/readyz` —— 就绪探针
  (ping DB + Redis,任一挂了返 `503`)。
- `/metrics` —— Prometheus 指标(HTTP 请求、后台 worker、构建信息)。
  **安全:`/metrics` 必须只对内网开放** —— 不要经公网 ingress/nginx 路由出去;
  只在网络 / 集群内部抓取。
- 审计日志是主要安全信号 —— 查 `mxid_audit_log` 表或接告警 webhook。

## 离线(内网)安装与升级

适用于无外网的站点,以及企业版镜像——它在私有 GHCR 包里,集群本来就拉不到。
做法是搬一个 tar 包过去,现场不拉任何东西。

**在能访问 ghcr.io 的机器上**(企业版先 `docker login ghcr.io`):

```bash
make offline-bundle TAG=v1.8.0             # 企业版;社区版加 EDITION=ce
# -> mxid-offline-ee-v1.8.0.tar.gz  (约 80-200 MB)
```

包里含 chart 需要的**全部三个镜像**、打包好的 Helm chart、values 模板和
`SHA256SUMS`。第三个镜像最容易漏也最致命:`busybox`,`waitForDeps` 初始化容器要用,
漏了所有 Pod 都会卡在 `Init:ImagePullBackOff`。

**站点内首次安装:**

```bash
tar xzf mxid-offline-ee-v1.8.0.tar.gz && cd mxid-offline
mkdir -p /opt/mxid && cp values.example.yaml /opt/mxid/values.yaml
$EDITOR /opt/mxid/values.yaml          # 填 URL、数据库/Redis、密钥
./install.sh --registry harbor.internal/mxid --values /opt/mxid/values.yaml
```

**之后每次升级:**

```bash
tar xzf mxid-offline-ee-v1.9.0.tar.gz    # 还是解到 mxid-offline/
cd mxid-offline && ./install.sh
```

不论哪个版本,解开后目录都固定叫 `mxid-offline/`——版本号只在 tar 包名上
(你要能分辨手里是哪个版本,回滚时也得留旧包),但路径永不变,所以运维手册和
脚本不会写死版本号。新包直接解到旧目录上就是预期用法;`install.sh` 按
`manifest.env` 选 chart,旧版本残留的文件不会被误用。

不用带参数,也不用重填。`values.yaml` 要放在 bundle **外面**:
每次发版 bundle 都会被换掉,站点配置不该跟着一起丢。安装成功后,registry、
namespace、release 名和 values 路径会记进 `site.conf`
(`/etc/mxid/site.conf`,否则 `~/.config/mxid/`),后续运行自动读回。
万一这个文件丢了,会退而从集群里已部署的 Helm release 反查。显式参数永远优先,
所以临时覆盖某一项不影响记住的配置。

**任何 OCI registry 都支持**——Harbor、Nexus、ECR、普通 `registry:2` 都行。
包里的镜像带的是原始 `ghcr.io/...` 名字(`docker save` 就是这么记的),
`install.sh` 会按你给的 `--registry` 重打 tag。Harbor 有两个坑要注意:
先 `docker login`;并且**项目要预先建好**——Harbor 推送时不会自动建项目,
报错信息还很难懂。

`install.sh` 会校验 checksum、把镜像导入 docker / nerdctl / ctr、重打 tag 推到你的
registry 前缀下,再执行 `helm upgrade --install`,同时把 `image.registry` 和
`backend.waitForDeps.image` 指过去。加 `--dry-run` 可以先演练。仓库名必须保持
`mxid` / `mxid-ee` / `mxid-web` / `busybox`——chart 的 helper 就是按这些名字拼接的。

推镜像**之前**会先校验 values,因为 chart 对缺失密钥是 fail-closed:
`databasePassword`、`cryptoKeyEncryptionKey`、`auditChainKey`、`auditAnchorKey`
四个都必填(最后一个是因为 `audit.anchorSink.enabled` 默认为 `true`,不想要锚定就把它设成
`false`)。每个用 `openssl rand -base64 32` 生成,并且**务必备份**:
`cryptoKeyEncryptionKey` 丢了,所有已存密文永久不可恢复。

如果确实没有内部 registry,可以用 `./install.sh --load-only` 把镜像导进本地运行时——
但必须**每个节点**都跑一遍,并设置 `image.pullPolicy=IfNotPresent`,而且以后新加的节点还得再跑。
强烈建议用 registry。

升级就是换个新版本的包跑同样的命令。回滚就跑旧版本的包;镜像从不打 `latest`,
钉哪个版本就是哪个版本。

## 升级

1. 读 [CHANGELOG.md](../CHANGELOG.md) 看目标版本说明。
2. 备份数据库(`pg_dump`)。
3. 改 `MXID_TAG` 到新版,`docker compose pull && up -d`。迁移启动时自动跑。
4. 验证关键 SP 的集成手册(控制台 `/admin/docs`)仍通过。

> **从 < v1.7.2 升级:** v1.7.2 修了 SPA 缓存头 —— `index.html` 现在按
> `Cache-Control: no-cache` 下发(每次都重新验证),带 hash 的 `/assets/*`
> 保持 immutable,之后的升级都会干净地铺开。缓存了 v1.7.2 之前 `index.html`
> 的浏览器可能还会显示一次旧 SPA —— 升级后让用户强刷一次
> (Ctrl/Cmd+Shift+R)即可,此后全自动。

## 排错

| 现象 | 可能原因 | 修法 |
|------|---------|------|
| OIDC token `iss` = `http://localhost:10050` | `ExternalURLs.IssuerURL` 空 + `config.IssuerURL` 是 localhost | 在控制台设 `ExternalURLs.IssuerURL` |
| CAS 应用返回 `application not found` | App `code` 不匹配 | `/protocol/cas/<code>/login` 路径段就是 DB `code` 列 |
| 设置保存后看不到 toast "已保存" | monorepo Tailwind `@source` 丢失 | 确认 `web/apps/<app>/src/index.css` 有 `@source "../../../packages/shared/src/**/*.{ts,tsx}"` |
| 门户登录重定向死循环 | cookie 域不匹配 | 设 `server.cookie_domain` 为共享父域 |
