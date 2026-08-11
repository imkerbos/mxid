# 身份绑定恢复 + 204 信封修复 — 设计文档

- 日期:2026-08-10
- 状态:待实施
- 触发:生产事故 —— 一名用户失去 Lark 登录能力,无任何功能性恢复手段

发版后本文移入 `docs/archive/`。

---

## 1. 事故经过

超管 SB 为用户 H(`Layne`,仅外部登录,无本地密码)重置 MFA。实际发生的事:

1. SB 在用户详情页 **身份绑定** tab 点了 `解绑`(本意是解绑 MFA,点错了 tab)。
   后端解绑成功,但接口返回 `204`,前端判定失败,弹出 **"删除失败"**。SB 以为没生效。
2. SB 转到 **MFA 因子** tab 点 `强制移除`。step-up 校验通过(toast "已验证"),
   后端删除成功,同样返回 `204`,前端再次弹出 **"删除失败"**。列表因走了失败分支未刷新,
   仍显示 TOTP 存在;另一名超管 A 在自己的会话里看到的才是真实状态(已删除)。
3. H 从 Lark 登录。绑定已不存在 → `auto_create=true` → `allocUsername` 发现 `Layne`
   被在世的原账号占用 → 自动建出空壳账号 **`Layne-1`**,H 的 Lark `external_id`
   被写到 `Layne-1` 名下。
4. SB 认为 `Layne-1` 是垃圾数据,删除之。用户表是软删(`deleted_at`),
   而 `mxid_user_identity` 的外键是 `ON DELETE CASCADE` —— **`UPDATE` 不触发 CASCADE**,
   于是那行携带正确 `external_id` 的绑定成为孤儿留在库里。
5. H 再次从 Lark 登录 → `GetIdentityByExternal` 命中孤儿绑定 →
   `GetByID(Layne-1)` 被 GORM 软删过滤 → not found →
   `external_login.go:74` 直接 `fmt.Errorf("get linked user")` 硬失败,
   **不回退 AutoCreate 分支** → 永久锁死。

结果:H 无法通过 Lark 登录,无法自动建号,且系统中不存在任何重建身份绑定的接口。

## 2. 根因

### 2.1 Bug A — `204 No Content` 撞前端信封契约

后端:

```go
// internal/domain/user/handler.go:499
c.JSON(http.StatusNoContent, nil)   // 204, Content-Type: application/json, body 长度 0
```

前端成功拦截器:

```js
// web/packages/shared/src/api/client.ts:128
const data = response.data          // "" —— 空 body 经 transformResponse 后是空串
if (data.code !== 0) {              // "".code === undefined ≠ 0 → 判定为失败
  return Promise.reject(new ApiError(data.code, data.message, data.detail, data.traceId))
}
```

`code` 为 `undefined`,`extractMessage` 落不到任何本地化分支,`e.message` 为空串,
于是 toast 只剩标题、没有副文案 —— 与事故截图一致。

已实测复现:

- gin `httptest`:`status=204 content-type="application/json; charset=utf-8" body="" len=0`
- Node 复刻拦截器 + 真 axios + 真 json-bigint:`RAW data = "" typeof string` → `interceptor REJECTS (code = undefined)`

受影响的五个接口,全部是"执行成功却报告失败":

| 位置 | 功能 | 写法 |
|---|---|---|
| `internal/domain/user/handler.go:398` | 解绑身份 | `c.JSON(204, nil)` |
| `internal/domain/user/handler.go:499` | 强制移除 MFA 因子 | `c.JSON(204, nil)` |
| `internal/domain/authn/admin_session_handler.go:105` | 撤销用户全部会话 | `c.JSON(204, nil)` |
| `internal/domain/authn/admin_session_handler.go:147` | 撤销单个会话 | `c.JSON(204, nil)` |
| `internal/domain/access/handler.go:198` | 删除访问资格策略 | `response.NoContent(c)` |

第五处走的是 `pkg/response/response.go:126` 的 `NoContent` helper,症状相同 ——
前端 `AccessEligibility.tsx:290` 会误报"删除资格策略失败"。
`internal/domain/access/handler_test.go:329` 断言了 `w.Code == 204`,
把错误行为固化进了测试,修复时必须一并改掉。

删除用户走的是 `response.OK(c, nil)`(`handler.go:187`),信封正常,因此**静默成功** —— 这是第 4 步的前提。

### 2.2 Bug B — 软删用户导致外部 IdP 永久锁死

1. `repository_impl.go:243` 用户软删,只 `UPDATE mxid_user SET deleted_at`
2. `migrations/000002_init_user.up.sql:61` 的 `ON DELETE CASCADE` 对 `UPDATE` 无效 → 绑定行成孤儿
3. `external_login.go:52` `GetIdentityByExternal` 命中孤儿(`repository_impl.go:597` 不检查关联用户是否已删)
4. `external_login.go:73` `GetByID` 被软删过滤 → not found
5. `external_login.go:74` 硬失败,不回退 AutoCreate

**2026-08-10 实施期间更正:此处原本还断言了第二个失败点,该断言不成立。**

原文称:清掉孤儿绑定放行 AutoCreate 后仍会二次失败,因为 `allocUsername`(`external_login.go:219`)
用过滤软删的 `GetByUsername` 判断用户名可用,而 `UNIQUE(tenant_id, username)` 没有 `deleted_at` 谓词。

该结论来自只读 `migrations/000002_init_user.up.sql:21` 的裸 `UNIQUE(tenant_id, username)`,
没有往后核查该约束是否被后续迁移改过。实际上 **`migrations/000047_user_username_soft_delete_unique`
(2026-07-04)早已把它换成 partial 唯一索引** `idx_user_tenant_username ... WHERE deleted_at IS NULL`,
且该迁移的注释描述的正是同一个失效链条 —— 五周前就有人踩过并修好了。

因此软删的 `Layne-1` **并不占用**用户名,auto-provision 不会二次撞唯一键。
锁死 H 的是本节 1-5 步那条链(孤儿绑定 → `GetByID` 被软删过滤 → 硬失败不回退 AutoCreate),
与用户名唯一键无关。原计划中为此新增迁移 `000069` 的任务已作废并跳过。

**遗留待核查(运维,非代码)**:dev 库 `schema_migrations.version = 68`。
若某个生产实例的迁移版本 **低于 47**,则该实例上此问题真实存在 —— 需要核对实际发生事故那套环境的迁移版本。

### 2.3 结构性缺口 — 身份绑定是单向门

`mxid_user_identity` 的行**只能**由外部 IdP 首次登录时自动创建。

- Console:`handler.go:62-63` 只有 `GET` + `DELETE`
- Portal:`security_handler.go:112` 只有 `GET`

`DeleteIdentity`(`repository_impl.go:452`)是硬删,`UserIdentity` 模型(`model.go:116-127`)无 `DeletedAt`。
解绑即永久,系统内无任何重建入口。这是设计缺口,不止是本次事故的表现。

## 3. 目标 / 非目标

**目标**

1. 任何写操作不得再"执行成功却报告失败"
2. 误点解绑可撤销
3. 用户能自助恢复外部身份绑定,无需管理员接触 `external_id`
4. 软删用户不再导致外部 IdP 永久锁死,且管理员可恢复已删用户
5. 用纯功能路径恢复用户 H,不执行手工 SQL

**非目标**

- Portal 自助**解绑**(YAGNI:绑定内容由 OAuth 决定而非用户填写,绑错概率低)
- 管理员手工填写 `external_id` 建立绑定(已评估否决,见 §7.2)
- 改动 `一键离职`(已评估,该功能设计正确,见 §7.3)

## 4. 数据模型

### 迁移 `000068_user_identity_soft_delete`

```sql
-- up
ALTER TABLE mxid_user_identity ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_user_identity_deleted_at ON mxid_user_identity (deleted_at);

-- 唯一键必须同步 partial 化，否则软删行继续占用 external_id，重新绑定必撞唯一键。
-- 约束是内联声明的，名字由 Postgres 自动生成，因此动态查找而非硬编码名字。
DO $$
DECLARE cname TEXT;
BEGIN
  SELECT conname INTO cname
  FROM pg_constraint
  WHERE conrelid = 'mxid_user_identity'::regclass AND contype = 'u';
  IF cname IS NOT NULL THEN
    EXECUTE format('ALTER TABLE mxid_user_identity DROP CONSTRAINT %I', cname);
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS uk_user_identity_external
  ON mxid_user_identity (tenant_id, provider_type, external_id)
  WHERE deleted_at IS NULL;
```

`down` 反向:删 partial 索引、恢复 `UNIQUE` 约束、删列与索引。
恢复 `UNIQUE` 前需先物理删除软删行,否则可能因历史重复而失败 —— `down` 中明确执行
`DELETE FROM mxid_user_identity WHERE deleted_at IS NOT NULL;`。

模型 `internal/domain/user/model.go` 的 `UserIdentity` 增加:

```go
DeletedAt gorm.DeletedAt `gorm:"column:deleted_at;index" json:"-"`
```

加上该字段后 GORM 的 `Delete` 自动变为软删,`GetIdentityByExternal` 等既有查询自动排除软删行。
`DeleteIdentity`(`repository_impl.go:452`)的实现无需改动。

### ~~迁移 `000069_user_username_partial_unique`~~ —— 已作废,不实施

实施期间发现 `migrations/000047_user_username_soft_delete_unique`(2026-07-04)已经做了完全相同的事。
再加一条只会得到第二个同义但异名的唯一索引(`IF NOT EXISTS` 只按名字判重,不按定义)。
详见 §2.2 的更正说明。以下内容仅作记录保留。

```sql
-- up
DO $$
DECLARE cname TEXT;
BEGIN
  SELECT conname INTO cname
  FROM pg_constraint
  WHERE conrelid = 'mxid_user'::regclass AND contype = 'u'
    AND pg_get_constraintdef(oid) LIKE '%username%';
  IF cname IS NOT NULL THEN
    EXECUTE format('ALTER TABLE mxid_user DROP CONSTRAINT %I', cname);
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS uk_user_tenant_username
  ON mxid_user (tenant_id, username) WHERE deleted_at IS NULL;
```

与 email/phone 索引(`000002_init_user.up.sql:24-27`)口径对齐。
partial 化只放松约束不收紧,不会因存量数据失败。

## 5. 后端设计

### 5.1 信封统一

五处改为 `response.OK(c, nil)`,回归全站 `{code, message, data}` 信封。
前端 `deleteMFA` / `unbindIdentity` / 会话撤销 / 删除资格策略的调用点无需改动。

`pkg/response/response.go:126` 的 `NoContent` helper 随之删除 —— 留着它就是留着下一次踩坑的入口。
`internal/domain/access/handler_test.go:329` 的 204 断言改为断言 200 + `code == 0`。

**守卫测试**:新增扫描源码的 Go 测试,禁止 `internal/**` 的 handler 出现
`http.StatusNoContent`,白名单仅放行 CORS preflight(`internal/middleware/cors.go:39`)。
与仓库既有的 `verify-gormtags`、`exhaustruct` 同一思路 —— 不变量由测试固化,不依赖 review。
按 `CONTRIBUTING.md` 的要求,守卫先在"打回原状"的代码上验证它确实会失败。

### 5.2 解绑改软删,新增恢复

repository 与 service 新增:

- `ListDeletedIdentities(ctx, userID) ([]*UserIdentity, error)` — 用 `Unscoped()` 查 `deleted_at IS NOT NULL`
- `RestoreIdentity(ctx, userID, identityID) error` — 置 `deleted_at = NULL`

`RestoreIdentity` 前置校验:目标 `external_id` 是否已被**在世**绑定占用。
占用则拒绝并返回新错误码,不静默覆盖。

新增 console 路由(两条都必须登记 `app/authz_console.go` 的 `consoleProtectedRoutes`,
否则被硬 deny 网关 403):

```
GET  /api/v1/console/users/:id/identities/deleted        authz.Require("user.read")
POST /api/v1/console/users/:id/identities/:iid/restore   authz.Require("user.identity.manage")
```

`IsHighRiskConsole`(`internal/domain/authn/stepup.go:41`)目前只把 `DELETE` 判为高危,
因此需把 `/identities/:iid/restore` 加入 `highRiskWriteSuffixes`,让恢复同样吃 step-up。

两条路由均记录审计(who / ip / when / what / result)。

### 5.3 绑定 seam(CE)与自助绑定(EE)

按 §7.1 的结论,身份关联规则留在 CE,协议部分留在 EE。

**CE 侧** — `pkg/ee/registry/seam.go` 新增,与既有的 `ExternalLoginFunc`(`seam.go:43`)对称:

```go
// BindIdentityInput is the neutral binding contract between an external IdP
// callback (EE) and the CE user domain. Mirrors ResolverInput (seam.go:26) but
// carries the already-authenticated local user instead of auto-provision knobs:
// the caller is logged in, so there is nothing to provision.
type BindIdentityInput struct {
	TenantID     int64
	UserID       int64 // the logged-in local user the identity attaches to
	ProviderType string
	ProviderID   string
	ExternalID   string
	DisplayName  string
	Raw          map[string]any
}

// BindIdentityFunc links an already-authenticated external identity to an
// existing local user. Implemented by the CE user domain.
type BindIdentityFunc func(ctx context.Context, in *BindIdentityInput) error
```

CE 实现承载**占用冲突三分支**:

| `external_id` 当前状态 | 处理 |
|---|---|
| 未被占用 | 建立绑定 |
| 绑定在**在世**用户身上 | 拒绝,返回专用错误码"该外部账号已绑定到其他账号" |
| 绑定在**已删除**用户身上 | **允许接管**,把绑定转移到当前用户,记高危审计 |

第三分支的安全依据:调用方已完成 OAuth,证明其控制该 `external_id`;
而占用方是已被管理员删除的账号,不存在活跃用户的身份被夺走。
这正是用户 H 的情形(`external_id` 挂在软删的 `Layne-1` 上)。

**EE 侧** — `mxid-ee/features/externalidp`:

```
POST /api/v1/portal/security/identities/bind/:idpCode   → 302 到 IdP 授权页
```

回调复用现有 handler,靠 state 中的意图位分流"登录"与"绑定"。

- state 存 Redis,内容为 `userID + nonce + intent=bind + TTL`,与当前 portal 会话绑死。
  回调时 state 中的 `userID` 必须等于当前会话 `userID`,否则拒绝 —— 防止绑定劫持。
- 复用 `internal/gateway/portal/security_handler.go:241` 的 step-up helper,
  与 console 共用同一个 sudo 窗口。
- 无 MFA 因子的用户命中 `mfa_enroll_required`,前端已有 `CODE_MFA_ENROLL_REQUIRED`
  事件导航到 enroll 页 —— 用户先绑 TOTP 再绑外部身份,不构成死锁。

### 5.4 软删用户不再锁死

1. `service.Delete` 软删用户时,级联软删其 identity 绑定。
   FK CASCADE 对 `UPDATE` 无效,只能在应用层做。

2. `ResolveExternalLogin` 分流。**注意顺序陷阱**:做完第 1 条后
   `GetIdentityByExternal` 会直接 not-found,于是走 AutoCreate 建新号 —— 与既定策略相反。
   因此补一次查询:not-found 时再查软删绑定,命中且其关联用户已删 →
   返回 `ErrExternalUserDeleted` + 专用错误码,portal 显示"账号已被删除,请联系管理员"。

   既定策略:**已删用户从外部 IdP 登录一律拒绝并提示,绝不自动重建、绝不自动恢复。**
   删除是管理员意图,不应被一次登录静默推翻;恢复必须走管理员显式入口。

3. 新增管理员恢复已删用户:

```
POST /api/v1/console/users/:id/restore    authz.Require("user.restore")
```

同样需要 `consoleProtectedRoutes` 登记、加入 `highRiskWriteSuffixes` 吃 step-up、记审计。
与身份恢复相互独立,各管各的:恢复用户不自动恢复其绑定,反之亦然。

新增业务码三个,登记到 `pkg/errcode/catalog.go`:

| 常量 | 含义 | 触发点 |
|---|---|---|
| `NumExternalIDTaken` | 该外部账号已绑定到其他账号 | 自助绑定三分支之"在世占用";恢复绑定时的占用校验 |
| `NumExternalUserDeleted` | 账号已被删除,请联系管理员 | `ResolveExternalLogin` 命中已删用户的绑定 |
| `NumIdentityAlreadyBound` | 该绑定已存在,无需恢复 | 恢复一条其实未被软删的绑定 |

数字在实施时从未占用号段分配。按名字引用,不使用数字字面量,
且不复用任何已被前端本地化的码 —— 复用会让用户看到错误的句子。

## 6. 前端设计

- **Console / 身份绑定 tab**
  - 解绑确认文案改写,区分"登录方式"与"二次验证":
    > 解除后,该用户将无法再通过 {{provider}} 登录 MXID。这不会影响其 MFA 设置。可在下方"已解绑"中恢复。
  - 新增"已解绑身份"折叠区,每项带 `恢复` 按钮
- **Console / 用户列表**:已删用户可见 + 恢复入口
- **Portal / 账号安全页**:身份绑定区,每个已启用的外部 IdP 一个 `绑定` 按钮;已绑定的显示状态
- **`client.ts` 防御**:成功拦截器在读取信封前先放行无 body 响应

```js
// 204/205 carry no body per HTTP spec; an empty body is not an envelope.
if (response.status === 204 || response.status === 205 || data === '' || data == null) {
  return response
}
```

  后端已统一为 200 信封,这层是防止未来再次引入 204 的兜底。

所有写操作按仓库规范给 `toast.success` / `toast.error`,不得静默。
UI 原语从 `@mxid/shared` 引入。i18n 中英双语同步。

## 7. 已评估并否决的方案

### 7.1 把自助绑定整块放进 EE

否决。身份关联属于核心身份模型,协议适配才属于插件 —— Keycloak 的 `FederatedIdentity`
关联逻辑在核心而 IdP 只是 provider SPI,Okta 的 linking 规则在核心策略引擎而
connector 只负责协议。共同点是"这个外部身份归谁"是授权决策,不下放给协议插件。

本仓库已有对称先例:`seam.go:43` 的 `ExternalLoginFunc` —— EE 跑完 OAuth 拿到
`external_id` 后回调 CE 做账号关联。绑定沿用同一模式。

具体理由:

1. "已删用户占用 → 允许接管"这条规则决定谁能获得谁的身份,必须在 CE 的开源可审计代码里,
   而非 EE 的 `garble` 混淆二进制中
2. 三分支可在 CE 直接单测,不必启动 OAuth 流程;EE 的 `garble -tiny` 另有历史坑
3. CE 将来接入其他身份源(LDAP、SCIM、其他联邦协议)可直接复用这套绑定语义

CE 无外部 IdP,portal 上不会出现绑定按钮;但软删恢复、204 修复、Bug B 修复 CE 全部受益。

### 7.2 管理员手工填写 `external_id` 建立绑定

否决。这是真实的提权向量:持有 `user.identity.manage` 的人填入他人的
`external_id`,即可把该外部身份接到自己控制的账号上,此后用那个外部账号登录进的是被接管的号。
step-up 与审计只能事后追责,拦不住。而超管普遍持有该权限。

自助绑定(用户自己走 OAuth)不存在该问题:用户只能绑定他实际控制的外部账号。
软删恢复也不存在:管理员只能恢复曾真实存在过的绑定,无法凭空指定 `external_id`。

### 7.3 给 `一键离职` 加二次确认

否决。`internal/domain/offboarding/service.go:170` 实际执行的是:

```
Disable(禁用，不删) → NotifyLogout(通知下游 SSO 应用注销) → KillAllByUser(踢会话)
→ 生成离职复核清单(每个可达应用一项) → 发 user.offboarded 审计事件
```

不删用户。确认框已写全后果,并明示"此操作可在恢复账号后撤销"。
失败语义分层正确:禁用失败中止,踢会话失败仅 warn 不回滚(账号已禁用,安全目标已达成)。

摩擦应加在不可逆、无声、后果延迟的操作上,而非所有危险操作上 ——
加错位置会训练出确认疲劳,削弱真正需要确认的那一道。

本次事故的第一个误操作是把"身份绑定 tab 的解绑"当成了"解绑 MFA"。
摩擦因此落在解绑确认文案上(见 §6),精准对应实际发生的误解。

## 8. 测试策略

| 测试 | 断言 |
|---|---|
| 源码扫描守卫 | `internal/**` handler 不出现 `http.StatusNoContent`(白名单 CORS) |
| `client.ts` 单测 | 204 响应不得 reject —— 由本次的 Node 复现脚本改写而来 |
| 解绑生命周期 | 解绑 → 在世列表不含 → 已解绑列表含 → 恢复 → 在世列表含 |
| 恢复冲突 | 恢复时 `external_id` 已被在世绑定占用 → 拒绝 |
| 自助绑定三分支 | 未占用 → 建;在世占用 → 拒;**已删占用 → 接管** |
| `ResolveExternalLogin` | 绑定指向已删用户 → 返 `ErrExternalUserDeleted`,**不得**走 AutoCreate |
| `allocUsername` | 存在同名软删用户时不再撞唯一键 —— 直接复刻 `Layne-1` 场景 |
| state 绑定 | 回调 state 的 `userID` 与当前会话不符 → 拒绝 |

## 9. 恢复用户 H 的操作路径(零 SQL)

前置:本设计发版。

1. 管理员在控制台用户详情页点 `设置密码`,给 H 设临时密码。
   `仅外部登录` 徽章只是 `HasUsablePassword`(`pkg/crypto/crypto.go:22-28`)的派生显示,
   判断密码哈希是否为占位符 `$2a$10$NO_LOCAL_PASSWORD_`,并非硬性拦截。
2. H 用账号密码登录 portal。若租户启用强制 MFA,此处会被引导先绑定 TOTP —— 顺带恢复了被误删的 MFA。
3. H 在账号安全页点 `绑定 Lark` → 走 OAuth → 命中"绑定在已删除用户身上" → 接管转移 → 记高危审计。
4. H 恢复 Lark 登录。管理员可在事后清理软删的 `Layne-1`。

## 10. 发版注意

- 迁移两条,均为放松约束,可安全前滚;`down` 已处理软删行的物理清理
- CE 与 EE 锁步同版本 tag,先推 CE tag
- 动了 `web/`,发版前必须跑 `pnpm -r build`
- `CHANGELOG.md` 在同一 commit 内更新
- 新增 env / helm 值:无
- 功能门变化:无(自助绑定依赖既有的 `external_idp` feature key)
- 本次事故另写一份复盘至 `docs/postmortems/2026-08-10-mfa-reset-identity-unbind-lockout.md`
