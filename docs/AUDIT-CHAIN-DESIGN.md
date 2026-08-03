# 防篡改审计底层设计 (Tamper-Proof Audit Log)

- 日期: 2026-07-05
- 状态: 设计已确认,待写实现计划
- 范围: 全局审计底层重构 —— 所有写操作 + 敏感读操作,不可篡改,可独立验证

## 1. 目标与非目标

### 目标 (以"经得起 code 审计"为标尺)
本质属性:**不存在任何一条能改状态、却不产生"可验证、append-only、防篡改记录"的代码路径。**

- 所有**写操作**(受审表的增/删/改)全量入链,一条不漏。
- 所有**应用层安全事件**(登录成功/失败、MFA、step-up、登出、token 签发/撤销、consent)入链。
- **敏感读操作**(查看密钥明文、导出用户数据、查询审计日志本身)入链。
- 记录**不可篡改**:哈希链 + DB 权限 append-only + Ed25519 签名的外部 Merkle 锚定。
- **可证明**:提供 verify / export 命令,第三方可离线独立验证某段日志未被改动。
- 每条记录带 before/after 全量状态。

### 非目标 (YAGNI,显式划边界)
- 普通读操作(列表/详情查询)不入链 —— 量大价值低,行业共识 (zitadel/Okta/等保 均不记每次读)。策略显式记录,不静默。
- 不做"拖时间轴重放历史状态"的重型 UI。before/after 已存,留作后门,将来可叠 projection。
- 不改业务写逻辑 —— 只在 ORM 层加 callback 拦截,domain 代码零改动 (回归风险最低)。

## 2. 核心管线

```
写操作
  ├─ gorm callback(受审表 create/update/delete)──┐
  ├─ app 安全事件(登录/MFA/token/...)────────────┤ 同一 DB 事务
  └─ 敏感读事件(看密钥/导出/查审计)──────────────┤
                                                  ▼
                        audit_pending (outbox, app 角色仅 INSERT)
                                  │  ← 原子:与状态变更同生共死,不丢
                        单线程 chainer (特权角色)
                                  │  ← 唯一序列化点,按 seq 排序算哈希链
                                  ▼
                        audit_log (append-only, 仅 chainer INSERT, app 无写权)
                                  │
                        每 N 条 / N 分钟 → Merkle root → Ed25519 签名 → 外部 WORM 汇
```

复用现有 `internal/outbox`。本质是**事务性 outbox 模式** —— 业界成熟、可审。

### 2.1 为什么用 outbox 而非"同事务直接写链"
- **捕获**(必须原子、不可丢)放进业务事务 → 写 `audit_pending` 一行。保证原子性 + 无绕过。
- **算链**(需序列化、防篡改)交给单线程 chainer 秒级离线完成 → 写 `audit_log`。热路径不锁链头,吞吐不受影响。避免"同租户所有写串行"的登录高频瓶颈。
- 窗口期(已捕获未上链):`audit_pending` 同事务持久化,不丢;chainer 消费幂等且按 seq 顺序,未上链条目是 pending 非 lost。捕获完整性与链防篡改**解耦**,各自满分。

## 3. 数据结构

### audit_pending (outbox; app 角色仅 INSERT, chainer 角色 SELECT/DELETE)
```
id           BIGINT PK
tenant_id    BIGINT
chain_class  TEXT      -- data | auth | admin | sensitive_read
actor_id     BIGINT NULL
actor_type   TEXT
event_type   TEXT
resource_type TEXT NULL
resource_id  BIGINT NULL
before       JSONB NULL   -- 变更前全量 (update/delete)
after        JSONB NULL   -- 变更后全量 (create/update)
ip           TEXT NULL
user_agent   TEXT NULL
geo_city     TEXT NULL
geo_country  TEXT NULL
session_id   TEXT NULL
detail       JSONB NULL
occurred_at  TIMESTAMPTZ
```

### audit_log (append-only; 仅 chainer 特权角色 INSERT)
```
seq          BIGINT     -- 每 (tenant_id, chain_class) 内单调连续;断号=被删
tenant_id    BIGINT
chain_class  TEXT
prev_hash    BYTEA      -- 上一条 entry_hash;genesis 为 32 字节 0
entry_hash   BYTEA      -- HMAC-SHA256(key, seq ‖ prev_hash ‖ canonical_json(payload))
key_id       TEXT       -- 支持密钥轮换,验证按 id 取 key
payload      JSONB      -- audit_pending 的全部业务字段 (含 before/after)
anchored_root_id BIGINT NULL  -- 被哪个 Merkle 锚点覆盖
imported     BOOLEAN DEFAULT false  -- 历史存量导入段,诚实标记不可追溯锚定
created_at   TIMESTAMPTZ
PRIMARY KEY (tenant_id, chain_class, seq)
```

### audit_anchor (外部锚点的本地索引)
```
id           BIGINT PK
tenant_id    BIGINT
chain_class  TEXT
from_seq     BIGINT
to_seq       BIGINT
merkle_root  BYTEA
signature    BYTEA      -- Ed25519 over merkle_root
key_id       TEXT
external_uri TEXT       -- 外部 WORM 汇位置
created_at   TIMESTAMPTZ
```

### chain_head (chainer 内部序列化状态; 每 (tenant, class) 一行)
```
tenant_id, chain_class, last_seq, last_entry_hash
PRIMARY KEY (tenant_id, chain_class)
```

`chain_class` 分链维度:`data`(ORM 数据变更) / `auth`(登录/MFA/token) / `admin`(治理操作) / `sensitive_read`(敏感读)。按 (tenant, class) 分链 → 跨租户/跨类并行,验证分段独立。

before/after 存全量 → 该流将来可叠 projection 重建状态(方案二后门)。

## 4. ORM 层强制 (消灭绕过点)

gorm 注册全局 callback: `Create/Update/Delete`。对**受审模型白名单**:
- Update/Delete 前:同事务 `SELECT` 抓 before。
- 取 after(写入值)+ 从 context 取 actor/ip/session (复用现有 `pkg/auditctx`)。
- 同事务 INSERT 一行 `audit_pending`。

**受审白名单** (初版): `user, app, approle, permission, access_grant, tenant, oidckey, apitoken, setting, conditionalaccess`。结构化维护;新增敏感表须显式登记,漏登记由测试断言报警 (见 §8)。

app 层语义事件 (登录/MFA/登出/token/consent) 与敏感读事件不是简单表写 → 走同一个 `audit.Emit()` API,也进 `audit_pending`。现有 `auditctx` 事件平迁至此。

审计员验证面:**一个 callback + 一张白名单**。受审表任何写不经 callback 无法落库;手写 `db.Save()` 亦触发 callback → 无绕过。

## 5. append-only 落到 DB 权限

- app 连库角色: `audit_log` 无 `UPDATE/DELETE/TRUNCATE`;`audit_pending` 仅 `INSERT`。
- chainer 独立特权角色(独立凭证): `audit_pending` SELECT/DELETE, `audit_log` INSERT。
- 保留期清理:独立特权任务,仅允许删「已锚定且超保留期」的段;删除动作本身记一条 `admin` 事件入链。
- 效果:app 被 RCE 也无 `audit_log` 写权限,改不了历史。靠数据库权限而非代码自觉。

## 6. 哈希链 + 外部锚定

### 链
- `entry_hash = HMAC-SHA256(key, canonical)`,`canonical = seq ‖ prev_hash ‖ canonical_json(payload)`。
- `canonical_json`: 键排序、无空白、null 显式。必须确定性 (验证需复算)。preimage 精确定义写入实现文档。
- genesis: `seq=0`, `prev_hash = 32 字节 0`,每 (tenant, class) 一条。
- key 走现有 KEK 保护; `key_id` 入库支持轮换,验证按 id 取对应 key,轮换不破坏旧验证。

### 锚定
- chainer 每 N 条 / N 分钟,对新增段算 **Merkle root** → **Ed25519 签名** (复用现有 license 签名基建) → 写外部 append-only 汇 (S3 Object Lock WORM 或独立只追加库) → 本地记 `audit_anchor`。

### 信任边界
- 仅哈希链:防"库被攻破" (DBA / SQL 注入 / 偷备份)。
- 攻击者同时拿 库 + KEK 可重算链 —— 但改不了已签名、已落在爆炸半径外的 Merkle root。
- 这是从"对 DBA 防篡改"升级到"法律级非抵赖"的关键。

## 7. 验证 + 导出 (可证明性)

### verify 命令
- 从 genesis 重算每条 entry_hash 比对。
- 检查 seq 连续 (断号 = 删除)。
- 比对 `audit_anchor` 的 Merkle root 与外部汇里签名的 root。
- 输出: `链已验证至 seq N,已锚定至 seq M,发现 0 处篡改`。

### export 命令
- 导出 seq 区间 + 该段链 + 前后最近的签名锚点。
- 第三方离线用 Ed25519 公钥独立验证该段未被改动。
- 格式: JSONL (条目) + `proof.json` (链段 + 签名锚点 + 公钥指纹)。

用途: 客户 demo / 安全白皮书 / 等保证据。

## 8. 查询 UI (轻量)

审计查看器:
- 按**时间段**过滤 (start/end) + 现有过滤维度 (actor / event_type / resource / keyword)。
- 每段/每条显示**验证状态**徽章 (已验证 / 已锚定 / 待锚定 / imported)。
- 不做拖时间轴重放历史状态的重型交互。

现有读 API (list/stats/keyword) 改指向 `audit_log`,加验证状态列。

## 9. 与现有 auditctx 的迁移

演化,非推倒:
- 现 `AuditLog` 表 + `auditctx` 中间件 → 演化为 **app 事件源**,喂进新管线 (actor/ip/geo/session/detail 全平迁)。
- 数据变更捕获 (ORM callback) 是新增能力。
- 现有读 API 改指向 `audit_log`,加验证状态列。
- 历史存量 `AuditLog`:一次性导入为 genesis 之后的初始段,标注 `imported=true` (不可追溯锚定,诚实标记)。

## 10. 测试 (安全核心,必须有)

- **篡改检测**: 改 `audit_log` 一行 payload → verify 失败并定位。
- **删除检测**: 删一行 → seq 断号报警。
- **原子性**: 业务事务回滚 → 无孤儿 pending;提交 → pending 必在。
- **并发**: 并行写 → chainer 产出连续有效链。
- **append-only**: app 角色 UPDATE/DELETE `audit_log` 被 DB 拒。
- **锚定**: 篡改后重算 Merkle root ≠ 签名 root。
- **覆盖**: 受审表白名单漏登记 → 测试断言"敏感表必在白名单"报警,防静默漏审。
- **敏感读**: 看密钥/导出/查审计触发入链。

## 11. 涉及模块

- `internal/domain/audit` —— 数据结构、chainer、verify/export、查询 API。
- `pkg/auditctx` —— actor/ip/session 上下文 (复用扩展)。
- `internal/outbox` —— audit_pending 消费。
- `internal/db` —— gorm callback 注册、DB 角色/权限迁移。
- `pkg/crypto` —— HMAC key (KEK 保护)、Ed25519 签名 (复用 license 基建)。
- `internal/db` migrations —— 新表 + DB 角色权限。

## 12. 未决/实现期确认

- 外部 WORM 汇选型: S3 Object Lock vs 独立只追加库 (部署环境决定,做成可插拔 sink)。
- 锚定频率 N 的默认值 (条数 + 时间双触发)。
- chainer 部署形态: 进程内 goroutine vs 独立进程 (独立凭证要求倾向独立,或进程内单例 + 独立 DB 连接角色)。
