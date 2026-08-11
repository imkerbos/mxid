# 身份绑定恢复 + 204 信封修复 — 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 消除"执行成功却报告失败"的信封缺陷,并给外部身份绑定补上恢复能力,使误删/误解绑可以纯功能路径修复。

**Architecture:** 四个阶段,每个阶段结束都是一个可独立发版的完整状态。Phase A 统一 HTTP 信封;Phase B 让身份绑定可软删可恢复;Phase C 修软删用户导致的外部 IdP 锁死;Phase D 加自助绑定(身份关联规则在 CE,OAuth 协议在 EE)。

**Tech Stack:** Go 1.25.12(Gin + GORM + Redis)、PostgreSQL 15、React 19 + Vite + TypeScript(pnpm workspaces)、golang-migrate、in-memory sqlite 作单测存储。

**设计文档:** `docs/2026-08-10-identity-rebind-and-204-envelope-design.md` —— 有疑问先回去看它,尤其是 §7 的三个"已评估并否决"。

## Global Constraints

- 回复用户用中文;代码、注释、commit、PR 一律英文。
- **每个任务末尾 commit 一次,只在本地 feature 分支上。** 分支是 `feat/identity-rebind-204-envelope`(CE 与 EE 各一条,均从 `dev` 开出)。commit 用 Conventional Commits,**不得**出现 Claude / AI / Anthropic 字样或 `Co-Authored-By` trailer。**绝不 push,绝不合并** —— 推送与合入 dev 由用户明确指示后另行执行,合并时 squash。
  各任务步骤里写"暂存并报告"的地方,一律按本条执行为 commit。
- 每个 console 写路由必须同时具备:`authz.Require(perm, scope)`、`authz.Protect`、`app/authz_console.go` 的 `consoleProtectedRoutes` 条目。缺一者运行时被硬 deny 网关 403。
- 每个写 API 必须记审计(who / ip / when / what / result)。
- 每个业务码必须登记 `pkg/errcode/catalog.go` 并按名字引用,禁止数字字面量。禁止复用已被前端本地化的码。
- 前端每个 save / create / delete / upload 必须给 `toast.success` / `toast.error`,禁止静默。UI 原语从 `@mxid/shared` 引入。
- i18n 中英双语同步(`zh-CN.ts` 与 `en-US.ts`),键结构镜像。
- 用户可见变更 → `CHANGELOG.md` 的 `[Unreleased]` 加 bullet,与代码同一 commit。
- GORM scan 结构体字段必须带显式 `gorm:"column:..."` tag(EE 走 `garble -tiny`,无 tag 字段会静默扫空)。
- 动了 `web/` 的任务,验证步骤包含 `pnpm -r build`,不能只跑 `tsc --noEmit`。
- 后端跑 `go build ./... && go vet ./...`;lint 用钉死的 golangci-lint v1.64.8。

---

# Phase A — HTTP 信封统一

**交付物:** 所有写接口返回 `{code:0}` 信封,前端不再把成功当失败。可单独发版。

## Task 1: 守卫测试 + 五处改为信封响应

先写守卫,让它在**当前未修复的代码上失败** —— 仓库的既定做法是守卫必须先证明自己抓得住它要抓的缺陷 ——
然后修掉五处,让守卫转绿。写守卫与修复是同一个任务:单独交付一个必然失败的测试不是可交付物。

**Files:**
- Create: `internal/httpguard/no_204_test.go`
- Modify: `internal/domain/user/handler.go:398`
- Modify: `internal/domain/user/handler.go:499`
- Modify: `internal/domain/authn/admin_session_handler.go:105`
- Modify: `internal/domain/authn/admin_session_handler.go:147`
- Modify: `internal/domain/access/handler.go:198`
- Modify: `pkg/response/response.go:125-128`(删除 `NoContent` helper)
- Modify: `internal/domain/access/handler_test.go:329`(断言从 204 改 200)
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: `response.OK(c *gin.Context, data any)`,来自 `pkg/response/response.go:55`
- Produces: 五个接口的响应体统一为 `{"code":0,"message":"ok","data":null,"traceId":"..."}`

- [ ] **Step 1: 写守卫测试**

新建 `internal/httpguard/no_204_test.go`:

```go
package httpguard

// Every write API answers with the {code,message,data} envelope. A 204 carries
// no body, so the SPA's success interceptor reads `data.code` off an empty
// string, sees undefined, and reports a successful delete as "删除失败" — the
// exact defect that cost a user their Lark login on 2026-08-10. This guard
// fails the build if a 204 ever reappears in a handler.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// allowed lists the only files permitted to answer 204. CORS preflight is a
// protocol-level empty response, not a business reply.
var allowed = map[string]bool{
	filepath.Join("internal", "middleware", "cors.go"): true,
}

func TestNoHandlerAnswers204(t *testing.T) {
	root := filepath.Join("..", "..")
	var offenders []string

	err := filepath.Walk(filepath.Join(root, "internal"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		if allowed[rel] {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		for i, line := range strings.Split(string(src), "\n") {
			if strings.Contains(line, "StatusNoContent") || strings.Contains(line, "response.NoContent(") {
				offenders = append(offenders, rel+":"+itoa(i+1)+" "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if len(offenders) > 0 {
		t.Fatalf("handlers must answer with the {code,message,data} envelope, not 204.\n"+
			"Use response.OK(c, nil) instead. Offenders:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
```

- [ ] **Step 2: 跑测试,确认它失败**

Run: `go test ./internal/httpguard/ -run TestNoHandlerAnswers204 -v`

Expected: FAIL,输出列出 5 个 offender:
```
internal/domain/user/handler.go:398
internal/domain/user/handler.go:499
internal/domain/authn/admin_session_handler.go:105
internal/domain/authn/admin_session_handler.go:147
internal/domain/access/handler.go:198
```

若列出的不是这 5 处,先停下核对 —— 说明代码基线与计划不符。

守卫此刻是红的,这是预期状态。下面的步骤让它转绿。

- [ ] **Step 3: 四处 `c.JSON(http.StatusNoContent, nil)` 改掉**

`internal/domain/user/handler.go` 的 398 与 499 行、`internal/domain/authn/admin_session_handler.go` 的 105 与 147 行,把

```go
	c.JSON(http.StatusNoContent, nil)
```

改成

```go
	response.OK(c, nil)
```

改完检查这两个文件的 import:若 `net/http` 不再被使用则删除该 import,若 `pkg/response` 尚未导入则补上。`go build` 会告诉你。

- [ ] **Step 4: 第五处改掉,并删除 helper**

`internal/domain/access/handler.go:198`:

```go
	response.NoContent(c)
```

改成

```go
	response.OK(c, nil)
```

然后删除 `pkg/response/response.go:125-128` 的整个 helper:

```go
// NoContent sends a 204 with no body. Used by DELETE handlers.
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}
```

留着它就是留着下一次踩坑的入口。

- [ ] **Step 5: 修掉固化了错误行为的断言**

`internal/domain/access/handler_test.go:329` 当前断言 `w.Code != http.StatusNoContent` 则失败。改为断言 200 + 信封 code 为 0:

```go
	if w.Code != http.StatusOK {
		t.Fatalf("delete eligibility: want 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	var env struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("delete eligibility: response body is not an envelope: %v (body=%s)", err, w.Body.String())
	}
	if env.Code != 0 {
		t.Fatalf("delete eligibility: want envelope code 0, got %d", env.Code)
	}
```

补 `encoding/json` import。

- [ ] **Step 6: 跑守卫 + 受影响的包**

```bash
go test ./internal/httpguard/ -run TestNoHandlerAnswers204 -v
go test ./internal/domain/access/... ./internal/domain/user/... ./internal/domain/authn/... 
go build ./... && go vet ./...
```

Expected: 守卫 PASS,其余全绿。

- [ ] **Step 7: 写 CHANGELOG**

`CHANGELOG.md` 的 `[Unreleased]` 下 `### Fixed` 加:

```markdown
- Admin writes that answered `204 No Content` — unbind identity, force-remove an MFA factor,
  revoke sessions, delete an access-eligibility policy — reported a successful operation as a
  failure in the console. The SPA reads the `{code,message,data}` envelope, and a 204 has no
  body to read it from. All five now answer `200` with the envelope.
```

- [ ] **Step 8: commit**

```bash
git add -A
git commit -m "fix(api): answer admin writes with the envelope, never 204

A 204 has no body, so the SPA's success interceptor read \`data.code\` off an
empty string, saw undefined, and reported a successful delete as a failure.
Unbind identity, force-remove an MFA factor, revoke sessions and delete an
access-eligibility policy all did this. A guard test now fails the build if a
handler answers 204 again."
```

## Task 2: 前端防御 + 回归单测

后端已统一为 200,这层是防止未来再次引入 204 的兜底。

**Files:**
- Modify: `web/packages/shared/src/api/client.ts:127-134`
- Create: `web/packages/shared/src/api/client.test.ts`

**Interfaces:**
- Consumes: `createApiClient(baseURL: string): AxiosInstance`,来自 `client.ts:107`
- Produces: 无

- [ ] **Step 1: 写失败测试**

新建 `web/packages/shared/src/api/client.test.ts`:

```ts
// A 204 has no body. The success interceptor used to read `data.code` off the
// resulting empty string, get undefined, and reject — turning every successful
// delete into a "删除失败" toast. Regression guard for the 2026-08-10 incident.

import http from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { createApiClient } from './client'

let server: http.Server
let baseURL = ''

beforeAll(async () => {
  server = http.createServer((req, res) => {
    if (req.url === '/empty-204') {
      res.writeHead(204, { 'Content-Type': 'application/json; charset=utf-8' })
      res.end()
      return
    }
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify({ code: 0, message: 'ok', data: null }))
  })
  await new Promise<void>((resolve) => server.listen(0, resolve))
  baseURL = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
})

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()))
})

describe('createApiClient response interceptor', () => {
  it('does not reject a 204 with an empty body', async () => {
    const client = createApiClient(baseURL)
    const res = await client.delete('/empty-204')
    expect(res.status).toBe(204)
  })

  it('still resolves a normal 200 envelope', async () => {
    const client = createApiClient(baseURL)
    const res = await client.get('/ok')
    expect(res.data.code).toBe(0)
  })
})
```

- [ ] **Step 2: 跑测试,确认第一条失败**

```bash
cd web && pnpm --filter @mxid/shared test -- client.test.ts
```

Expected: `does not reject a 204 with an empty body` FAIL。

若 `@mxid/shared` 尚未配置 vitest,先加最小配置:`package.json` 的 `scripts.test` 设为 `vitest run`,并 `pnpm add -D vitest` 到该 workspace。配置属于本任务的一部分,不另开任务。

- [ ] **Step 3: 加防御**

`web/packages/shared/src/api/client.ts:127` 起,成功拦截器改为:

```ts
    (response: AxiosResponse<ApiResponse>) => {
      // 204/205 carry no body per the HTTP spec, and a proxy can hand back an
      // empty body on any status. Neither is an envelope — reading `.code` off
      // one yields undefined and turns a success into a failure toast.
      const data = response.data
      if (response.status === 204 || response.status === 205 || data === '' || data == null) {
        return response
      }
      if (data.code !== 0) {
        return Promise.reject(new ApiError(data.code, data.message, data.detail, data.traceId))
      }
      return response
    },
```

- [ ] **Step 4: 跑测试 + 全量构建**

```bash
cd web && pnpm --filter @mxid/shared test -- client.test.ts && pnpm -r build
```

Expected: 两条测试 PASS,构建绿。

- [ ] **Step 5: 暂存并报告**

```bash
git add -A && git status --short
```

**Phase A 完成 —— 此处是一个可发版点。**

---

# Phase B — 身份绑定软删与恢复(CE)

**交付物:** 解绑可撤销,管理员能在控制台恢复误解绑的身份。可单独发版。

## Task 3: 迁移 + 模型加软删

**Files:**
- Create: `migrations/000068_user_identity_soft_delete.up.sql`
- Create: `migrations/000068_user_identity_soft_delete.down.sql`
- Modify: `internal/domain/user/model.go:116-127`

**Interfaces:**
- Consumes: 无
- Produces: `UserIdentity.DeletedAt gorm.DeletedAt` —— 后续任务据此依赖 GORM 的软删语义

- [ ] **Step 1: 写迁移 up**

`migrations/000068_user_identity_soft_delete.up.sql`:

```sql
-- Identity bindings were hard-deleted, so an admin mis-click on "unbind" was
-- irreversible and left the user unable to sign in through their external IdP.
ALTER TABLE mxid_user_identity ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_user_identity_deleted_at ON mxid_user_identity (deleted_at);

-- The unique key must become partial in the same step. A soft-deleted row would
-- otherwise keep occupying (tenant_id, provider_type, external_id) and every
-- re-bind would collide with a row nobody can see. The constraint is declared
-- inline in 000002, so its name is Postgres-generated — look it up rather than
-- betting on the generated name.
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

- [ ] **Step 2: 写迁移 down**

`migrations/000068_user_identity_soft_delete.down.sql`:

```sql
-- Restoring the total unique constraint requires physically removing the rows
-- that only the partial index tolerated.
DELETE FROM mxid_user_identity WHERE deleted_at IS NOT NULL;

DROP INDEX IF EXISTS uk_user_identity_external;

ALTER TABLE mxid_user_identity
  ADD CONSTRAINT mxid_user_identity_tenant_id_provider_type_external_id_key
  UNIQUE (tenant_id, provider_type, external_id);

DROP INDEX IF EXISTS idx_user_identity_deleted_at;
ALTER TABLE mxid_user_identity DROP COLUMN IF EXISTS deleted_at;
```

- [ ] **Step 3: 模型加字段**

`internal/domain/user/model.go` 的 `UserIdentity` 结构体,在 `UpdatedAt` 之后加:

```go
	DeletedAt    gorm.DeletedAt `gorm:"column:deleted_at;index" json:"-"`
```

补 `gorm.io/gorm` import(该文件可能已有)。**不要**改 `DeleteIdentity` 的实现 —— 加了这个字段之后 GORM 的 `Delete` 自动变软删,`GetIdentityByExternal` 等既有查询自动排除软删行,这正是要的语义。

- [ ] **Step 4: 跑迁移 + 验证语义**

```bash
make migrate-up
go build ./... && go vet ./...
go test ./internal/domain/user/...
```

Expected: 迁移成功,既有测试全绿。

若 `external_login_tx_test.go` 挂了,大概率是 sqlite 的 AutoMigrate 与新字段的交互 —— 先读错误再动,不要绕过。

- [ ] **Step 5: 验证软删确实生效**

临时手工验证(不入库):

```bash
docker exec -i mxid-postgres-dev psql -U postgres -d mxid -c "\d mxid_user_identity" | grep -E "deleted_at|uk_user_identity_external"
```

Expected: 能看到 `deleted_at` 列和 `uk_user_identity_external` partial 索引。

- [ ] **Step 6: 暂存并报告**

```bash
git add -A && git status --short
```

## Task 4: 错误码登记

先登记码,后面的任务直接引用,避免各自造数字。

**Files:**
- Modify: `pkg/errcode/catalog.go`

**Interfaces:**
- Produces: `errcode.NumExternalIDTaken`、`errcode.NumExternalUserDeleted`、`errcode.NumIdentityAlreadyBound`

- [ ] **Step 1: 加常量**

在 `pkg/errcode/catalog.go` 的 `40901 NumConflict` 附近(冲突族)加三个常量。**先 grep 确认号码未被占用**:

```bash
grep -nE "4090[2-9]|4041[0-9]" pkg/errcode/catalog.go
```

用未占用的号码,以下用 `40902/40903/40904` 举例 —— 若已被占用,顺延并同步改后续任务里的引用:

```go
	NumExternalIDTaken      = 40902 // external account already bound to a live user
	NumIdentityAlreadyBound = 40903 // the binding is already active; nothing to restore
	NumExternalUserDeleted  = 40904 // the account behind this external identity was deleted
```

- [ ] **Step 2: 加 catalog 描述**

在描述表里加三行。**三个都标 `Generic`,不要标 `Localized`** —— `Localized` 表示 SPA 用固定句子替换服务端消息,这三个码的文案由前端按码分支处理,不走 `Localized` 通道:

```go
	NumExternalIDTaken:      {Generic, "external account already bound to a live user"},
	NumIdentityAlreadyBound: {Generic, "identity binding is already active"},
	NumExternalUserDeleted:  {Generic, "the account behind this external identity was deleted"},
```

- [ ] **Step 3: 跑 catalog 守卫**

```bash
go test ./pkg/errcode/...
go build ./...
```

Expected: PASS。仓库有测试守卫未登记码与重复码,这一步会抓到号码冲突。

- [ ] **Step 4: 暂存并报告**

```bash
git add -A && git status --short
```

## Task 5: repository —— 列出与恢复软删绑定

**Files:**
- Modify: `internal/domain/user/repository.go:72-80`(Identity 段)
- Modify: `internal/domain/user/repository_impl.go`(`DeleteIdentity` 之后,约 `:463`)
- Create: `internal/domain/user/identity_restore_test.go`

**Interfaces:**
- Consumes: `NewGormRepository(db *gorm.DB) Repository`
- Produces:
  - `ListDeletedIdentities(ctx context.Context, userID int64) ([]*UserIdentity, error)`
  - `RestoreIdentity(ctx context.Context, userID, identityID int64) error`
  - `GetLiveIdentityByExternal(ctx context.Context, tenantID int64, providerType, providerID, externalID string) (*UserIdentity, error)`
  - `GetAnyIdentityByExternal(ctx context.Context, tenantID int64, providerType, providerID, externalID string) (*UserIdentity, error)` —— 含软删,Phase C 用

- [ ] **Step 1: 写失败测试**

新建 `internal/domain/user/identity_restore_test.go`:

```go
package user

// Unbinding an identity used to be a one-way door: the row was hard-deleted and
// no API could recreate it. These tests pin the round trip — unbind hides the
// binding, restore brings it back — and the guard that stops a restore from
// silently stealing an external account away from a live user.

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newIdentityTestRepo(t *testing.T) (Repository, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&User{}, &UserDetail{}, &UserIdentity{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewGormRepository(db), db
}

func seedIdentity(t *testing.T, db *gorm.DB, id, userID int64, externalID string) *UserIdentity {
	t.Helper()
	now := time.Now().UTC()
	i := &UserIdentity{
		ID: id, UserID: userID, TenantID: 1,
		ProviderType: "lark", ProviderID: "p1", ExternalID: externalID,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := db.Create(i).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	return i
}

func TestUnbindThenRestoreRoundTrip(t *testing.T) {
	repo, db := newIdentityTestRepo(t)
	ctx := context.Background()
	seedIdentity(t, db, 10, 1, "ext-1")

	if err := repo.DeleteIdentity(ctx, 1, 10); err != nil {
		t.Fatalf("unbind: %v", err)
	}

	live, err := repo.ListIdentities(ctx, 1)
	if err != nil {
		t.Fatalf("list live: %v", err)
	}
	if len(live) != 0 {
		t.Fatalf("unbind must hide the binding, still see %d", len(live))
	}

	gone, err := repo.ListDeletedIdentities(ctx, 1)
	if err != nil {
		t.Fatalf("list deleted: %v", err)
	}
	if len(gone) != 1 || gone[0].ID != 10 {
		t.Fatalf("unbound binding must remain recoverable, got %+v", gone)
	}

	if err := repo.RestoreIdentity(ctx, 1, 10); err != nil {
		t.Fatalf("restore: %v", err)
	}

	live, err = repo.ListIdentities(ctx, 1)
	if err != nil {
		t.Fatalf("list live after restore: %v", err)
	}
	if len(live) != 1 || live[0].ID != 10 {
		t.Fatalf("restore must bring the binding back, got %+v", live)
	}
}

func TestRestoreRefusesWhenExternalIDTakenByLiveBinding(t *testing.T) {
	repo, db := newIdentityTestRepo(t)
	ctx := context.Background()

	seedIdentity(t, db, 10, 1, "ext-1")
	if err := repo.DeleteIdentity(ctx, 1, 10); err != nil {
		t.Fatalf("unbind: %v", err)
	}
	// Someone else picked up the same external account in the meantime.
	seedIdentity(t, db, 11, 2, "ext-1")

	err := repo.RestoreIdentity(ctx, 1, 10)
	if err == nil {
		t.Fatal("restore must refuse: ext-1 now belongs to a live binding on another user")
	}
}

func TestGetLiveIdentityByExternalIgnoresSoftDeleted(t *testing.T) {
	repo, db := newIdentityTestRepo(t)
	ctx := context.Background()
	seedIdentity(t, db, 10, 1, "ext-1")
	if err := repo.DeleteIdentity(ctx, 1, 10); err != nil {
		t.Fatalf("unbind: %v", err)
	}

	if _, err := repo.GetLiveIdentityByExternal(ctx, 1, "lark", "p1", "ext-1"); err == nil {
		t.Fatal("live lookup must not see a soft-deleted binding")
	}
	got, err := repo.GetAnyIdentityByExternal(ctx, 1, "lark", "p1", "ext-1")
	if err != nil {
		t.Fatalf("unscoped lookup must still find it: %v", err)
	}
	if got.ID != 10 {
		t.Fatalf("want binding 10, got %d", got.ID)
	}
}
```

- [ ] **Step 2: 跑测试,确认失败**

```bash
go test ./internal/domain/user/ -run "TestUnbindThenRestore|TestRestoreRefuses|TestGetLiveIdentity" -v
```

Expected: 编译失败,提示 `ListDeletedIdentities` / `RestoreIdentity` / `GetLiveIdentityByExternal` / `GetAnyIdentityByExternal` 未定义。

- [ ] **Step 3: 扩接口**

`internal/domain/user/repository.go` 的 Identity 段(现有 `GetIdentityByExternal` 声明之后)加:

```go
	// ListDeletedIdentities returns the bindings an admin unbound, so a
	// mis-click can be undone. Ordinary listing never shows these.
	ListDeletedIdentities(ctx context.Context, userID int64) ([]*UserIdentity, error)
	// RestoreIdentity clears deleted_at. Refuses when the external account has
	// since been claimed by a live binding — restoring over it would move
	// somebody else's login into this account.
	RestoreIdentity(ctx context.Context, userID, identityID int64) error
	// GetLiveIdentityByExternal is GetIdentityByExternal under its intent-revealing
	// name: soft-deleted bindings are invisible to it.
	GetLiveIdentityByExternal(ctx context.Context, tenantID int64, providerType, providerID, externalID string) (*UserIdentity, error)
	// GetAnyIdentityByExternal also sees soft-deleted bindings. Needed to tell
	// "never bound" apart from "bound to an account that was deleted".
	GetAnyIdentityByExternal(ctx context.Context, tenantID int64, providerType, providerID, externalID string) (*UserIdentity, error)
```

- [ ] **Step 4: 实现**

`internal/domain/user/repository_impl.go`,在 `DeleteIdentity` 之后加:

```go
// ListDeletedIdentities returns this user's soft-deleted bindings, newest first.
func (r *gormRepository) ListDeletedIdentities(ctx context.Context, userID int64) ([]*UserIdentity, error) {
	var out []*UserIdentity
	err := r.db.WithContext(ctx).
		Unscoped().
		Where("user_id = ? AND deleted_at IS NOT NULL", userID).
		Order("deleted_at DESC").
		Find(&out).Error
	if err != nil {
		return nil, fmt.Errorf("list deleted user identities: %w", err)
	}
	return out, nil
}

// RestoreIdentity clears deleted_at on a binding this user previously had.
// Scoped by both user_id and identity id so a stale id from one user cannot
// resurrect another user's binding.
func (r *gormRepository) RestoreIdentity(ctx context.Context, userID, identityID int64) error {
	var target UserIdentity
	err := r.db.WithContext(ctx).
		Unscoped().
		Where("user_id = ? AND id = ?", userID, identityID).
		First(&target).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return gorm.ErrRecordNotFound
		}
		return fmt.Errorf("load identity for restore: %w", err)
	}
	if !target.DeletedAt.Valid {
		return ErrIdentityAlreadyBound
	}

	// The external account may have been claimed while this binding was gone.
	// Restoring over a live binding would hand somebody else's login to this
	// account, so refuse and let a human resolve it.
	var clash int64
	err = r.db.WithContext(ctx).
		Model(&UserIdentity{}).
		Where("tenant_id = ? AND provider_type = ? AND external_id = ? AND id <> ?",
			target.TenantID, target.ProviderType, target.ExternalID, target.ID).
		Count(&clash).Error
	if err != nil {
		return fmt.Errorf("check external id availability: %w", err)
	}
	if clash > 0 {
		return ErrExternalIDTaken
	}

	err = r.db.WithContext(ctx).
		Unscoped().
		Model(&UserIdentity{}).
		Where("user_id = ? AND id = ?", userID, identityID).
		Updates(map[string]any{"deleted_at": nil, "updated_at": time.Now()}).Error
	if err != nil {
		return fmt.Errorf("restore user identity: %w", err)
	}
	return nil
}

// GetLiveIdentityByExternal finds a binding, ignoring soft-deleted ones.
func (r *gormRepository) GetLiveIdentityByExternal(ctx context.Context, tenantID int64, providerType, providerID, externalID string) (*UserIdentity, error) {
	return r.GetIdentityByExternal(ctx, tenantID, providerType, providerID, externalID)
}

// GetAnyIdentityByExternal finds a binding including soft-deleted ones.
func (r *gormRepository) GetAnyIdentityByExternal(ctx context.Context, tenantID int64, providerType, providerID, externalID string) (*UserIdentity, error) {
	var out UserIdentity
	err := r.db.WithContext(ctx).
		Unscoped().
		Where("tenant_id = ? AND provider_type = ? AND provider_id = ? AND external_id = ?",
			tenantID, providerType, providerID, externalID).
		Order("deleted_at IS NULL DESC").
		First(&out).Error
	if err != nil {
		return nil, err
	}
	return &out, nil
}
```

注意 `Count` 那一段**不加** `Unscoped()` —— 要数的正是"在世"绑定。

- [ ] **Step 5: 加哨兵错误**

在 `internal/domain/user` 定义错误的文件里(与 `ErrIdentityNotFound` 同处,grep 找)加:

```go
	// ErrExternalIDTaken means the external account is already bound to a live
	// user, so restoring or binding would move somebody else's login.
	ErrExternalIDTaken = errors.New("external id already bound")
	// ErrIdentityAlreadyBound means the binding is active; there is nothing to restore.
	ErrIdentityAlreadyBound = errors.New("identity already bound")
```

- [ ] **Step 6: 跑测试**

```bash
go test ./internal/domain/user/ -run "TestUnbindThenRestore|TestRestoreRefuses|TestGetLiveIdentity" -v
go build ./... && go vet ./...
```

Expected: 三条全 PASS。

- [ ] **Step 7: 暂存并报告**

```bash
git add -A && git status --short
```

## Task 6: service + console 路由

**Files:**
- Modify: `internal/domain/user/service.go`(`UnbindIdentity` 之后,约 `:843`)
- Modify: `internal/domain/user/handler.go:60-67`(路由段)+ 新 handler
- Modify: `internal/domain/user/errcodes.go`(域错误到错误码的绑定;grep `ErrIdentityNotFound` 定位)
- Modify: `app/authz_console.go`
- Modify: `internal/domain/authn/stepup.go:28-35`(`highRiskWriteSuffixes`)

**Interfaces:**
- Consumes: Task 5 的四个 repo 方法;Task 4 的三个错误码
- Produces:
  - `Service.ListDeletedIdentities(ctx, userID int64) ([]*UserIdentity, error)`
  - `Service.RestoreIdentity(ctx, userID, identityID int64) error`
  - `GET  /api/v1/console/users/:id/identities/deleted`
  - `POST /api/v1/console/users/:id/identities/:iid/restore`

- [ ] **Step 1: service 方法**

`internal/domain/user/service.go`,`UnbindIdentity` 之后加:

```go
// ListDeletedIdentities returns bindings an admin previously unbound.
func (s *Service) ListDeletedIdentities(ctx context.Context, userID int64) ([]*UserIdentity, error) {
	return s.repo.ListDeletedIdentities(ctx, userID)
}

// RestoreIdentity undoes an unbind. Emits identity_restored so the audit trail
// shows who handed the external login back and when.
func (s *Service) RestoreIdentity(ctx context.Context, userID, identityID int64) error {
	if err := s.repo.RestoreIdentity(ctx, userID, identityID); err != nil {
		if dberr.IsNotFound(err) {
			return ErrIdentityNotFound
		}
		return err
	}
	s.eventBus.Publish(ctx, event.Event{
		Type:    event.UserUpdated,
		Payload: map[string]any{"user_id": userID, "action": "identity_restored", "identity_id": identityID},
	})
	return nil
}
```

`RestoreIdentity` 直接透传 `ErrExternalIDTaken` / `ErrIdentityAlreadyBound`,由 errcode 绑定层映射。

- [ ] **Step 2: 绑定错误码**

在 `internal/domain/user/errcodes.go` 的映射表里加(照抄该文件既有条目的写法):

```go
	ErrExternalIDTaken:      {errcode.NumExternalIDTaken, http.StatusConflict},
	ErrIdentityAlreadyBound: {errcode.NumIdentityAlreadyBound, http.StatusConflict},
```

- [ ] **Step 3: handler**

`internal/domain/user/handler.go`,`UnbindIdentity` 之后加:

```go
// ListDeletedIdentities handles GET /users/:id/identities/deleted. Feeds the
// console's "unbound" section so a mis-clicked unbind can be undone.
func (h *Handler) ListDeletedIdentities(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	items, err := h.svc.ListDeletedIdentities(c.Request.Context(), id)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}
	out := make([]*UserIdentityResponse, len(items))
	for i, idt := range items {
		out[i] = ToIdentityResponse(idt)
	}
	response.OK(c, out)
}

// RestoreIdentity handles POST /users/:id/identities/:iid/restore.
func (h *Handler) RestoreIdentity(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	iid, err := strconv.ParseInt(c.Param("iid"), 10, 64)
	if err != nil {
		response.BadRequest(c, errcode.NumInvalidInput, "invalid identity id")
		return
	}
	if err := h.svc.RestoreIdentity(c.Request.Context(), id, iid); err != nil {
		h.handleServiceError(c, err)
		return
	}
	response.OK(c, nil)
}
```

`ToIdentityResponse` 若不存在,从 `ListIdentities`(`handler.go:351-378`)里把构造 `UserIdentityResponse` 的那段抽成函数,两处共用 —— 不要复制粘贴。

- [ ] **Step 4: 注册路由**

`internal/domain/user/handler.go` 的路由段,在现有 identity 两行之后加:

```go
		users.GET("/:id/identities/deleted", authz.Require("user.read", nil), h.ListDeletedIdentities)
		users.POST("/:id/identities/:iid/restore", authz.Require("user.identity.manage", nil), h.RestoreIdentity)
```

- [ ] **Step 5: 登记 authz + step-up**

`app/authz_console.go` 加两条(按文件里的排序位置插入,它是有序表):

```go
	{http.MethodGet, "/api/v1/console/users/:id/identities/deleted"},
	{http.MethodPost, "/api/v1/console/users/:id/identities/:iid/restore"},
```

`internal/domain/authn/stepup.go` 的 `highRiskWriteSuffixes` 加:

```go
	"/identities/:iid/restore",     // hand an external login back to a user
```

`IsHighRiskConsole` 只把 `DELETE` 判为高危,restore 是 POST,不加这条就不吃 step-up。

- [ ] **Step 6: 验证接线**

```bash
go build ./... && go vet ./...
go test ./app/... ./internal/domain/user/...
```

`app/` 下有启动期检查会核对路由是否都登记,漏登记会在这里被抓到。

再起 dev 栈用 curl 确认中间件顺序(仓库踩过 `.Use` 只作用于其后注册路由的坑):

```bash
make dev-up
curl -i -X POST http://localhost:3500/api/v1/console/users/1/identities/2/restore
```

Expected: 401(未认证),**不是** 404。404 说明路由没挂上。

- [ ] **Step 7: 暂存并报告**

```bash
git add -A && git status --short
```

## Task 7: console 前端 —— 已解绑区 + 解绑文案

**Files:**
- Modify: `web/packages/shared/src/api/user.ts`
- Modify: `web/apps/console/src/pages/users/detail.tsx:612-690`(`IdentitiesTab`)
- Modify: `web/packages/shared/src/i18n/locales/zh-CN.ts`
- Modify: `web/packages/shared/src/i18n/locales/en-US.ts`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: Task 6 的两个接口
- Produces: `userApi.listDeletedIdentities(id)`、`userApi.restoreIdentity(id, iid)`

- [ ] **Step 1: 加 API 方法**

`web/packages/shared/src/api/user.ts`,照 `unbindIdentity` 的写法加:

```ts
  listDeletedIdentities: (id: UID) =>
    client.get<ApiResponse<UserIdentity[]>>(`/users/${id}/identities/deleted`).then((r) => r.data.data),
  restoreIdentity: (id: UID, iid: UID) =>
    client.post<ApiResponse<null>>(`/users/${id}/identities/${iid}/restore`),
```

具体 client 变量名与返回约定照抄同文件既有条目。

- [ ] **Step 2: 改解绑确认文案**

`zh-CN.ts` 的 `users.detail.identitiesTab.confirmUnbind` 改为:

```ts
        confirmUnbind: '解除后，该用户将无法再通过 {{provider}} 登录 MXID。这不会影响其 MFA 设置。可在下方“已解绑”中恢复。',
```

`en-US.ts` 对应:

```ts
        confirmUnbind: 'After unbinding, this user can no longer sign in through {{provider}}. Their MFA settings are unaffected. You can restore it from "Unbound" below.',
```

这条文案是本次事故的直接对策:操作者当时把"解绑身份"当成了"解绑 MFA"。

- [ ] **Step 3: 加"已解绑"区的 i18n**

`zh-CN.ts` 的 `identitiesTab` 下加:

```ts
        unboundTitle: '已解绑',
        unboundEmpty: '没有已解绑的身份',
        restore: '恢复',
        confirmRestore: '恢复「{{provider}}」绑定？该用户将重新可以通过它登录。',
        restoreSuccess: '已恢复绑定',
        restoreFailed: '恢复绑定失败',
```

`en-US.ts` 镜像:

```ts
        unboundTitle: 'Unbound',
        unboundEmpty: 'No unbound identities',
        restore: 'Restore',
        confirmRestore: 'Restore the {{provider}} binding? The user will be able to sign in through it again.',
        restoreSuccess: 'Binding restored',
        restoreFailed: 'Failed to restore binding',
```

- [ ] **Step 4: 改 IdentitiesTab**

`detail.tsx` 的 `IdentitiesTab`:

1. 加 `const [deleted, setDeleted] = useState<UserIdentity[]>([])` 与 `const [restoring, setRestoring] = useState<string | null>(null)`
2. `load` 里并行取两个列表:

```tsx
  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [live, gone] = await Promise.all([
        userApi.listIdentities(userID),
        userApi.listDeletedIdentities(userID),
      ])
      setItems(live ?? [])
      setDeleted(gone ?? [])
    } finally {
      setLoading(false)
    }
  }, [userID])
```

3. 加恢复处理:

```tsx
  const confirmRestore = async () => {
    const it = restoreTarget
    if (!it) return
    setRestoreTarget(null)
    setRestoring(it.id)
    try {
      await userApi.restoreIdentity(userID, it.id)
      toast.success(t('users.detail.identitiesTab.restoreSuccess'))
      await load()
    } catch (e) {
      toast.error(t('users.detail.identitiesTab.restoreFailed'), extractMessage(e))
    } finally {
      setRestoring(null)
    }
  }
```

配套 `const [restoreTarget, setRestoreTarget] = useState<UserIdentity | null>(null)` 与一个 `ConfirmDialog`,照抄同文件 `delIdentity` 那套的写法。

4. 组件返回值末尾、在世列表之后渲染"已解绑"区。注意**顶部的早返回要改** —— 现在 `items.length === 0` 时直接返回空态,那样已解绑区永远看不见,而这恰恰是刚误解绑完最需要它的时刻:

```tsx
  if (items.length === 0 && deleted.length === 0) {
    return <div className="py-8 text-center text-sm text-faint">{t('users.detail.identitiesTab.empty')}</div>
  }
```

已解绑区本体:

```tsx
      {deleted.length > 0 && (
        <div className="mt-6">
          <h4 className="mb-2 text-xs font-medium uppercase tracking-wide text-faint">
            {t('users.detail.identitiesTab.unboundTitle')}
          </h4>
          <div className="space-y-2">
            {deleted.map((it) => (
              <div key={it.id} className="flex items-center justify-between rounded-lg border border-dashed border-border px-4 py-3 opacity-70">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-ink">{it.provider_type}</span>
                    <code className="rounded bg-surface-muted px-1.5 py-0.5 text-xs text-muted">{it.provider_id}</code>
                  </div>
                  <p className="mt-0.5 text-xs text-muted">
                    {it.external_name ? `${it.external_name} · ` : ''}{it.external_id}
                  </p>
                </div>
                <button
                  onClick={() => setRestoreTarget(it)}
                  disabled={restoring === it.id}
                  className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-faint hover:bg-surface-muted hover:text-ink disabled:opacity-50"
                >
                  {restoring === it.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RotateCcw className="h-3.5 w-3.5" />}
                  {t('users.detail.identitiesTab.restore')}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
```

`RotateCcw` 从 `lucide-react` import(同文件已从那里取 `Unlink` / `Loader2`)。

- [ ] **Step 5: 构建**

```bash
cd web && pnpm -r build
```

Expected: 绿。`tsc -b` 会抓到 per-app `tsc --noEmit` 漏掉的重复 i18n 键(TS1117),中英两份都改过了必须跑这个。

- [ ] **Step 6: 真机验证**

```bash
make dev-up
```

在控制台走一遍:解绑一个身份 → 确认 toast 是**成功**不是"删除失败"(Phase A 的效果)→ 已解绑区出现该项 → 点恢复 → 回到在世列表。

- [ ] **Step 7: CHANGELOG + 暂存**

`[Unreleased]` 的 `### Added` 加:

```markdown
- Unbinding an external identity is now reversible. The binding is soft-deleted and appears
  under "Unbound" on the user detail page, where an administrator can restore it. Previously
  an unbind was a one-way door with no API able to recreate the binding.
```

```bash
git add -A && git status --short
```

**Phase B 完成 —— 此处是一个可发版点。**

---

# Phase C — 软删用户不再锁死外部登录(CE)

**交付物:** 删除用户后,该外部身份的登录尝试得到明确拒绝而非硬失败;管理员可恢复已删用户;同名软删用户不再撞唯一键。

## ~~Task 8: username partial unique 迁移~~ —— 已作废,跳过

**实施期间作废。** `migrations/000047_user_username_soft_delete_unique`(2026-07-04,commit `aea0490`,
已在 `main`/`dev`/本分支)早已把 `UNIQUE(tenant_id, username)` 换成
`idx_user_tenant_username ... WHERE deleted_at IS NULL`,与 email/phone 索引口径一致。
dev 库实测确认该索引存在。再加一条 `000069` 只会产生第二个同义异名的唯一索引。

计划原文误判的来源:只读了 `000002_init_user.up.sql:21` 的裸 `UNIQUE(tenant_id, username)`,
未核查后续迁移是否改过它。设计文档 §2.2 已更正。

**遗留待核查(运维)**:若某生产实例迁移版本低于 47,该问题在那套环境上真实存在。

以下原文仅作记录保留,不执行。

**Files:**
- Create: `migrations/000069_user_username_partial_unique.up.sql`
- Create: `migrations/000069_user_username_partial_unique.down.sql`
- Create: `internal/domain/user/alloc_username_test.go`

**Interfaces:**
- Consumes: 无
- Produces: 无(schema 变更)

- [ ] **Step 1: 写复现测试**

新建 `internal/domain/user/alloc_username_test.go`:

```go
package user

// allocUsername asks GetByUsername whether a name is free, and GetByUsername
// filters soft-deleted rows — but UNIQUE(tenant_id, username) did not. So a name
// held by a soft-deleted user looked available and the INSERT then collided.
// This is exactly how "Layne-1" wedged auto-provisioning on 2026-08-10.

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newUsernameTestRepo(t *testing.T) (Repository, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&User{}, &UserDetail{}, &UserIdentity{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// AutoMigrate builds indexes from struct tags, which do not carry the
	// partial predicate. Recreate production's index by hand so the test is
	// actually exercising the constraint the migration installs.
	db.Exec(`DROP INDEX IF EXISTS uk_user_tenant_username`)
	if err := db.Exec(
		`CREATE UNIQUE INDEX uk_user_tenant_username ON mxid_user (tenant_id, username) WHERE deleted_at IS NULL`,
	).Error; err != nil {
		t.Fatalf("create partial index: %v", err)
	}
	return NewGormRepository(db), db
}

func TestSoftDeletedUsernameCanBeReused(t *testing.T) {
	repo, db := newUsernameTestRepo(t)
	ctx := context.Background()
	now := time.Now().UTC()

	first := &User{ID: 1, TenantID: 1, Username: "layne-1", PasswordHash: "x", CreatedAt: now, UpdatedAt: now}
	if err := db.Create(first).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := repo.Delete(ctx, 1); err != nil {
		t.Fatalf("soft delete: %v", err)
	}

	second := &User{ID: 2, TenantID: 1, Username: "layne-1", PasswordHash: "x", CreatedAt: now, UpdatedAt: now}
	if err := db.Create(second).Error; err != nil {
		t.Fatalf("a username freed by soft-delete must be reusable, got: %v", err)
	}
}
```

- [ ] **Step 2: 跑测试**

```bash
go test ./internal/domain/user/ -run TestSoftDeletedUsernameCanBeReused -v
```

这条在 sqlite 上建的是 partial 索引,所以会 PASS —— 它固化的是**迁移之后**的正确行为,防止未来有人把索引改回全量唯一。真正验证生产 schema 的是 Step 4。

- [ ] **Step 3: 写迁移**

`migrations/000069_user_username_partial_unique.up.sql`:

```sql
-- UNIQUE(tenant_id, username) in 000002 has no deleted_at predicate, while the
-- email and phone indexes right below it do. A soft-deleted user therefore kept
-- holding its username against allocUsername, which cannot see the row and
-- reports the name free — the INSERT then collides. Align username with them.
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

`migrations/000069_user_username_partial_unique.down.sql`:

```sql
-- The total constraint cannot coexist with usernames reused across a soft-delete.
DELETE FROM mxid_user WHERE deleted_at IS NOT NULL;

DROP INDEX IF EXISTS uk_user_tenant_username;

ALTER TABLE mxid_user
  ADD CONSTRAINT mxid_user_tenant_id_username_key UNIQUE (tenant_id, username);
```

- [ ] **Step 4: 跑迁移并在真库验证**

```bash
make migrate-up
docker exec -i mxid-postgres-dev psql -U postgres -d mxid -c "\d mxid_user" | grep -i username
```

Expected: 看到 `uk_user_tenant_username ... WHERE (deleted_at IS NULL)`,且原来的 `..._username_key` 约束已消失。

- [ ] **Step 5: 暂存并报告**

```bash
git add -A && git status --short
```

## Task 9: 删除用户时级联软删其绑定

**Files:**
- Modify: `internal/domain/user/service.go:467`(`Delete`)
- Modify: `internal/domain/user/repository.go`(Identity 段)
- Modify: `internal/domain/user/repository_impl.go`
- Create: `internal/domain/user/delete_cascade_test.go`

**Interfaces:**
- Consumes: 无
- Produces: `SoftDeleteIdentitiesByUser(ctx context.Context, userID int64) error`

- [ ] **Step 1: 写失败测试**

新建 `internal/domain/user/delete_cascade_test.go`:

```go
package user

// mxid_user_identity's FK is ON DELETE CASCADE, but user deletion is a soft
// delete — an UPDATE — and UPDATE does not fire CASCADE. The bindings were left
// orphaned, pointing at a user nobody could load. Deletion now sweeps them
// itself, in the application layer, because the database cannot.

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestDeleteUserSoftDeletesItsIdentities(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&User{}, &UserDetail{}, &UserIdentity{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := NewGormRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := db.Create(&User{ID: 1, TenantID: 1, Username: "layne-1", PasswordHash: "x", CreatedAt: now, UpdatedAt: now}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := db.Create(&UserIdentity{
		ID: 10, UserID: 1, TenantID: 1,
		ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-1",
		CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	if err := repo.SoftDeleteIdentitiesByUser(ctx, 1); err != nil {
		t.Fatalf("sweep identities: %v", err)
	}

	live, err := repo.ListIdentities(ctx, 1)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(live) != 0 {
		t.Fatalf("deleting a user must not leave live bindings behind, got %d", len(live))
	}
	gone, err := repo.ListDeletedIdentities(ctx, 1)
	if err != nil {
		t.Fatalf("list deleted: %v", err)
	}
	if len(gone) != 1 {
		t.Fatalf("the binding must remain recoverable, got %d", len(gone))
	}
}
```

- [ ] **Step 2: 跑测试,确认失败**

```bash
go test ./internal/domain/user/ -run TestDeleteUserSoftDeletesItsIdentities -v
```

Expected: 编译失败,`SoftDeleteIdentitiesByUser` 未定义。

- [ ] **Step 3: 加接口 + 实现**

`repository.go` 的 Identity 段:

```go
	// SoftDeleteIdentitiesByUser sweeps a user's bindings when the user is
	// soft-deleted. The FK is ON DELETE CASCADE, but a soft delete is an UPDATE
	// and UPDATE never fires CASCADE, so this has to happen in the app layer.
	SoftDeleteIdentitiesByUser(ctx context.Context, userID int64) error
```

`repository_impl.go`:

```go
// SoftDeleteIdentitiesByUser soft-deletes every binding belonging to a user.
func (r *gormRepository) SoftDeleteIdentitiesByUser(ctx context.Context, userID int64) error {
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Delete(&UserIdentity{}).Error
	if err != nil {
		return fmt.Errorf("soft delete user identities: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: 在 service.Delete 里调用**

`internal/domain/user/service.go:467` 的 `Delete`,在删用户**之前**扫绑定 —— 顺序很重要:先扫绑定后删用户,任一步失败时留下的是"用户还在但绑定没了"(可用 Phase B 的恢复修),反过来则留下"用户没了但绑定还在",正是这次事故的孤儿态。

```go
	// Sweep the identity bindings first. The FK is ON DELETE CASCADE but a soft
	// delete is an UPDATE, which never fires it. Order matters: if the sweep
	// succeeds and the user delete then fails, the recoverable state is "user
	// present, bindings restorable". The reverse leaves orphaned bindings
	// pointing at a user nobody can load — the shape that wedged Lark login.
	if err := s.repo.SoftDeleteIdentitiesByUser(ctx, id); err != nil {
		return fmt.Errorf("sweep identities: %w", err)
	}
```

- [ ] **Step 5: 跑测试**

```bash
go test ./internal/domain/user/... -v
go build ./... && go vet ./...
```

Expected: 全绿。

- [ ] **Step 6: 暂存并报告**

```bash
git add -A && git status --short
```

## Task 10: 外部登录遇到已删账号 —— 明确拒绝

**Files:**
- Modify: `internal/domain/user/external_login.go:47-86`
- Create: `internal/domain/user/external_login_deleted_test.go`
- Modify: `internal/domain/user/errcodes.go`

**Interfaces:**
- Consumes: Task 5 的 `GetAnyIdentityByExternal`;Task 4 的 `NumExternalUserDeleted`
- Produces: `ErrExternalUserDeleted`

**策略(设计文档 §5.4 已定):** 已删用户从外部 IdP 登录一律拒绝并提示,**绝不**自动重建、**绝不**自动恢复。删除是管理员意图,不该被一次登录静默推翻。

- [ ] **Step 1: 写失败测试**

新建 `internal/domain/user/external_login_deleted_test.go`:

```go
package user

// When the user behind a binding is deleted, ResolveExternalLogin used to wrap a
// record-not-found into a generic error and stop — no fallthrough to auto-create,
// no way for the caller to say anything useful. The user simply could not sign in
// and no message explained why. It must now name the situation.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestResolveExternalLoginRefusesDeletedAccount(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&User{}, &UserDetail{}, &UserIdentity{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	now := time.Now().UTC()
	if err := db.Create(&User{ID: 1, TenantID: 1, Username: "layne-1", PasswordHash: "x", CreatedAt: now, UpdatedAt: now}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := db.Create(&UserIdentity{
		ID: 10, UserID: 1, TenantID: 1,
		ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-1",
		CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	svc := newExternalLoginTestService(t, db)

	// Delete the user the way the admin API does.
	if err := svc.Delete(context.Background(), 1); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	// AutoCreate is on — the point is that it must NOT kick in and mint a
	// replacement account behind the administrator's back.
	_, err = svc.ResolveExternalLogin(context.Background(), &ExternalLoginInput{
		TenantID: 1, ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-1",
		Username: "layne", AutoCreate: true,
	})
	if !errors.Is(err, ErrExternalUserDeleted) {
		t.Fatalf("want ErrExternalUserDeleted, got %v", err)
	}

	var count int64
	db.Model(&User{}).Where("username LIKE ?", "layne%").Count(&count)
	if count != 0 {
		t.Fatalf("a deleted account must not be silently replaced, %d live users appeared", count)
	}
}
```

`newExternalLoginTestService` 在本仓库尚不存在,需要在本测试文件里新建。它是 Task 12 也要用的
共享装配,所以写成可复用的形式:

```go
// newExternalLoginTestService assembles a Service over an in-memory repo with
// just enough collaborators for the external-login paths: an id generator and
// a live event bus (the code publishes unconditionally, so a nil bus panics).
func newExternalLoginTestService(t *testing.T, db *gorm.DB) *Service {
	t.Helper()
	repo := NewGormRepository(db)
	svc := NewService(repo, /* 其余依赖按 NewService 的实际签名补齐 */)
	return svc
}
```

**动手前先读 `NewService` 的真实签名**(`grep -n "func NewService" internal/domain/user/service.go`),
按它逐个补齐参数:id 生成器用仓库现成的 snowflake 实现或一个自增桩,
event bus 用 `event.NewBus(zap.NewNop())`,其余可为 nil 的传 nil。
装配一次,C3 与 D1 两个测试文件共用 —— 放在先落地的那个文件里,另一个直接调用。

- [ ] **Step 2: 跑测试,确认失败**

```bash
go test ./internal/domain/user/ -run TestResolveExternalLoginRefusesDeletedAccount -v
```

Expected: FAIL —— `ErrExternalUserDeleted` 未定义。

- [ ] **Step 3: 加哨兵错误 + 改分流**

`internal/domain/user/external_login.go` 顶部加:

```go
// ErrExternalUserDeleted means the external identity maps to a local account an
// administrator deleted. Auto-provisioning must not paper over this: deletion is
// an administrative decision and a login attempt does not get to overrule it.
var ErrExternalUserDeleted = errors.New("external identity belongs to a deleted account")
```

`ResolveExternalLogin` 改两处。

第一处,`GetByID` 失败的分支(`:73-75`)—— 区分"用户被删"和其他错误:

```go
		u, err := s.repo.GetByID(ctx, binding.UserID)
		if err != nil {
			if dberr.IsNotFound(err) {
				// The binding is live but its user is gone: the account was
				// deleted before bindings were swept (pre-000068 data).
				return nil, ErrExternalUserDeleted
			}
			return nil, fmt.Errorf("get linked user: %w", err)
		}
```

第二处,not-found 分支进入 AutoCreate **之前**(`:79-84` 之间)—— 绑定已被级联软删的情况:

```go
	if !dberr.IsNotFound(err) {
		return nil, fmt.Errorf("lookup identity: %w", err)
	}

	// No live binding. Before provisioning, check whether one was swept away
	// with a deleted user. Auto-creating here would hand the external account a
	// brand-new empty profile and quietly undo the deletion.
	if prior, perr := s.repo.GetAnyIdentityByExternal(ctx, in.TenantID, in.ProviderType, in.ProviderID, in.ExternalID); perr == nil && prior != nil {
		return nil, ErrExternalUserDeleted
	}

	if !in.AutoCreate {
		return nil, ErrExternalUserNotLinked
	}
```

- [ ] **Step 4: 绑定错误码**

`internal/domain/user/errcodes.go` 加:

```go
	ErrExternalUserDeleted: {errcode.NumExternalUserDeleted, http.StatusForbidden},
```

- [ ] **Step 5: 跑测试**

```bash
go test ./internal/domain/user/... -v
go build ./... && go vet ./...
```

Expected: 全绿。既有的 external-login 测试也必须仍然绿 —— 若某条"无绑定则自动建号"的测试挂了,读它的 fixture:只有当该 external_id 从未绑定过时才该走 AutoCreate。

- [ ] **Step 6: 暂存并报告**

```bash
git add -A && git status --short
```

## Task 11: 恢复已删用户

**Files:**
- Modify: `internal/domain/user/repository.go`
- Modify: `internal/domain/user/repository_impl.go`
- Modify: `internal/domain/user/service.go`
- Modify: `internal/domain/user/handler.go`
- Modify: `app/authz_console.go`
- Modify: `internal/domain/authn/stepup.go`
- Modify: `web/packages/shared/src/api/user.ts`
- Modify: `web/apps/console/src/pages/users/index.tsx`
- Modify: i18n 两份 + `CHANGELOG.md`

**Interfaces:**
- Consumes: Task 9 的软删语义
- Produces:
  - `Repository.RestoreUser(ctx context.Context, id int64) error`
  - `Service.RestoreUser(ctx context.Context, id int64) error`
  - `POST /api/v1/console/users/:id/restore`
  - `userApi.restoreUser(id)`

- [ ] **Step 1: 写失败测试**

在 `internal/domain/user/delete_cascade_test.go` 追加:

```go
func TestRestoreUserBringsBackTheAccountButNotItsBindings(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&User{}, &UserDetail{}, &UserIdentity{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := NewGormRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := db.Create(&User{ID: 1, TenantID: 1, Username: "layne-1", PasswordHash: "x", CreatedAt: now, UpdatedAt: now}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := repo.Delete(ctx, 1); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := repo.GetByID(ctx, 1); err == nil {
		t.Fatal("deleted user must not be loadable")
	}

	if err := repo.RestoreUser(ctx, 1); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if _, err := repo.GetByID(ctx, 1); err != nil {
		t.Fatalf("restored user must be loadable: %v", err)
	}
}
```

绑定不随用户一起恢复,是刻意的:两者各走各的恢复入口,管理员对每一步都得明示。

- [ ] **Step 2: 跑测试,确认失败**

```bash
go test ./internal/domain/user/ -run TestRestoreUserBringsBack -v
```

Expected: `RestoreUser` 未定义。

- [ ] **Step 3: repo 实现**

`repository.go` 加 `RestoreUser(ctx context.Context, id int64) error`,`repository_impl.go` 实现:

```go
// RestoreUser clears deleted_at on a soft-deleted account. Its identity bindings
// stay unbound — restoring them is a separate, separately-audited decision.
func (r *gormRepository) RestoreUser(ctx context.Context, id int64) error {
	result := r.db.WithContext(ctx).
		Unscoped().
		Model(&User{}).
		Where("id = ? AND deleted_at IS NOT NULL", id).
		Updates(map[string]any{"deleted_at": nil, "updated_at": time.Now()})
	if result.Error != nil {
		return fmt.Errorf("restore user: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
```

- [ ] **Step 4: service + handler + 路由**

service:

```go
// RestoreUser undoes a soft delete.
func (s *Service) RestoreUser(ctx context.Context, id int64) error {
	if err := s.repo.RestoreUser(ctx, id); err != nil {
		if dberr.IsNotFound(err) {
			return ErrUserNotFound
		}
		return err
	}
	s.eventBus.Publish(ctx, event.Event{
		Type:    event.UserUpdated,
		Payload: map[string]any{"user_id": id, "action": "user_restored"},
	})
	return nil
}
```

handler:

```go
// RestoreUser handles POST /users/:id/restore.
func (h *Handler) RestoreUser(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	if err := h.svc.RestoreUser(c.Request.Context(), id); err != nil {
		h.handleServiceError(c, err)
		return
	}
	response.OK(c, nil)
}
```

路由:

```go
		users.POST("/:id/restore", authz.Require("user.restore", nil), h.RestoreUser)
```

`app/authz_console.go` 加 `{http.MethodPost, "/api/v1/console/users/:id/restore"}`;
`stepup.go` 的 `highRiskWriteSuffixes` 加 `"/restore"` —— 注意这条后缀同时覆盖用户恢复与 Task 6 的身份恢复,不必重复登记,但要确认它不会误伤其他以 `/restore` 结尾的既有路由:

```bash
grep -rn '"/restore"\|/restore"' --include="*.go" internal app | grep -v _test
```

若有其他 `/restore` 路由且不该吃 step-up,改用更精确的后缀。

- [ ] **Step 5: 用户列表加已删筛选与恢复入口**

后端 `List` 需支持返回已删用户。

1. `internal/domain/user/handler.go` 的 `ListUsersRequest` 加字段:

```go
	// IncludeDeleted surfaces soft-deleted accounts so an administrator can find
	// and restore one. Off by default — the ordinary list must stay clean.
	IncludeDeleted bool `form:"include_deleted"`
```

2. `Repository.List` 的查询参数结构体加同名字段,`repository_impl.go` 的实现里:

```go
	q := r.db.WithContext(ctx).Model(&User{})
	if p.IncludeDeleted {
		q = q.Unscoped()
	}
```

具体接法照抄该方法现有的条件拼装风格(先 `grep -n "func (r \*gormRepository) List" internal/domain/user/repository_impl.go` 读一遍)。

3. 响应 DTO(`internal/domain/user/dto.go`)加 `DeletedAt *string \`json:"deleted_at,omitempty"\``,
   在 `ToResponse` 里从 `u.DeletedAt.Time` 格式化(仅当 `u.DeletedAt.Valid`)。前端据此区分已删行。

4. 前端 `users/index.tsx` 加"显示已删除"开关(状态进查询参数),已删行整行降低不透明度并显示
   `恢复` 按钮,调用 `userApi.restoreUser(id)`,成功/失败各给 toast,成功后刷新列表。

i18n 两份加:

```ts
        showDeleted: '显示已删除',
        restoreUser: '恢复账号',
        confirmRestoreUser: '恢复账号「{{username}}」？其外部身份绑定需另行恢复。',
        restoreUserSuccess: '账号已恢复',
        restoreUserFailed: '恢复账号失败',
```

英文镜像同结构。

- [ ] **Step 6: 验证**

```bash
go test ./internal/domain/user/... ./app/...
go build ./... && go vet ./...
cd web && pnpm -r build
```

再起 dev 栈端到端走:删用户 → 列表勾"显示已删除"看到它 → 恢复 → 正常。

- [ ] **Step 7: CHANGELOG + 暂存**

`### Added`:

```markdown
- Deleted accounts can be restored from the console user list. Previously a soft-deleted user
  had no recovery path, and an external-IdP login against it failed with an opaque error
  instead of saying the account was deleted.
```

`### Fixed`:

```markdown
- Deleting a user left its external-identity bindings orphaned: the FK is `ON DELETE CASCADE`
  but a soft delete is an `UPDATE`, which never fires it. Sign-in through the external IdP then
  wedged permanently. Bindings are now swept with the user, and a login against a deleted
  account is refused with a message that says so.
```

~~`UNIQUE(tenant_id, username)` had no `deleted_at` predicate while the email and phone indexes
did, so a soft-deleted account kept holding its username against auto-provisioning.~~

**Struck, do not carry into the CHANGELOG.** Same defect as Task 8 (line 1136): this constraint
was already partial-indexed by `000047_user_username_soft_delete_unique`, five weeks before this
branch. Task 8 was voided for the same reason but this copy of the bullet, embedded in Task 11's
own CHANGELOG step, survived that correction and was carried into `CHANGELOG.md` in good faith by
a later implementer. Found and fixed post-hoc in Task 17.

```bash
git add -A && git status --short
```

**Phase C 完成 —— 此处是一个可发版点。**

---

# Phase D — 自助绑定(CE 规则 + EE 协议)

**交付物:** 用户能在 portal 自助把外部账号绑回自己名下,这是恢复用户 H 的路径。

## Task 12: CE 绑定规则 + 三分支

**Files:**
- Modify: `internal/domain/user/external_login.go`
- Create: `internal/domain/user/bind_identity_test.go`

**Interfaces:**
- Consumes: Task 5 的 `GetLiveIdentityByExternal` / `GetAnyIdentityByExternal`;Task 4 的 `NumExternalIDTaken`
- Produces:

```go
type BindIdentityInput struct {
	TenantID     int64
	UserID       int64
	ProviderType string
	ProviderID   string
	ExternalID   string
	DisplayName  string
	Raw          map[string]any
}

func (s *Service) BindExternalIdentity(ctx context.Context, in *BindIdentityInput) error

// 本任务顺带新增的 repo 方法（Step 3 给了实现）
RestoreIdentityTo(ctx context.Context, i *UserIdentity) error
```

三分支(设计文档 §5.3):

| `external_id` 状态 | 处理 |
|---|---|
| 未被占用 | 建立绑定 |
| 绑在**在世**用户身上 | 拒绝,`ErrExternalIDTaken` |
| 绑在**已删除**用户身上 | 接管,转移到当前用户,记高危审计 |

- [ ] **Step 1: 写失败测试**

新建 `internal/domain/user/bind_identity_test.go`:

```go
package user

// Self-service binding is the only path that recovers an external login without
// an administrator ever typing an external_id — typing one would let anyone with
// user.identity.manage graft a colleague's Lark account onto an account they
// control. Here the caller has completed OAuth, which proves they hold the
// external account; the only question left is who currently holds it locally.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newBindTestFixture(t *testing.T) (*Service, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&User{}, &UserDetail{}, &UserIdentity{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	now := time.Now().UTC()
	for _, u := range []*User{
		{ID: 1, TenantID: 1, Username: "layne", PasswordHash: "x", CreatedAt: now, UpdatedAt: now},
		{ID: 2, TenantID: 1, Username: "other", PasswordHash: "x", CreatedAt: now, UpdatedAt: now},
		{ID: 3, TenantID: 1, Username: "layne-1", PasswordHash: "x", CreatedAt: now, UpdatedAt: now},
	} {
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("seed user %d: %v", u.ID, err)
		}
	}
	return newExternalLoginTestService(t, db), db
}

func bindInput(userID int64) *BindIdentityInput {
	return &BindIdentityInput{
		TenantID: 1, UserID: userID,
		ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-1",
		DisplayName: "Layne",
	}
}

func TestBindCreatesWhenExternalIDIsFree(t *testing.T) {
	svc, db := newBindTestFixture(t)
	if err := svc.BindExternalIdentity(context.Background(), bindInput(1)); err != nil {
		t.Fatalf("bind: %v", err)
	}
	var got UserIdentity
	if err := db.Where("external_id = ?", "ext-1").First(&got).Error; err != nil {
		t.Fatalf("binding must exist: %v", err)
	}
	if got.UserID != 1 {
		t.Fatalf("binding must attach to the caller, got user %d", got.UserID)
	}
}

func TestBindRefusesWhenHeldByLiveUser(t *testing.T) {
	svc, db := newBindTestFixture(t)
	now := time.Now().UTC()
	if err := db.Create(&UserIdentity{
		ID: 10, UserID: 2, TenantID: 1,
		ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-1",
		CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	err := svc.BindExternalIdentity(context.Background(), bindInput(1))
	if !errors.Is(err, ErrExternalIDTaken) {
		t.Fatalf("want ErrExternalIDTaken, got %v", err)
	}
}

func TestBindTakesOverWhenHeldByDeletedUser(t *testing.T) {
	svc, db := newBindTestFixture(t)
	now := time.Now().UTC()
	// user 3 is the "layne-1" shell that auto-provisioning minted and an admin
	// then deleted, taking the real external_id down with it.
	if err := db.Create(&UserIdentity{
		ID: 10, UserID: 3, TenantID: 1,
		ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-1",
		CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := svc.Delete(context.Background(), 3); err != nil {
		t.Fatalf("delete shell account: %v", err)
	}

	if err := svc.BindExternalIdentity(context.Background(), bindInput(1)); err != nil {
		t.Fatalf("takeover from a deleted account must succeed: %v", err)
	}

	var live []UserIdentity
	if err := db.Where("external_id = ?", "ext-1").Find(&live).Error; err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(live) != 1 || live[0].UserID != 1 {
		t.Fatalf("exactly one live binding must remain, owned by the caller; got %+v", live)
	}
}
```

- [ ] **Step 2: 跑测试,确认失败**

```bash
go test ./internal/domain/user/ -run TestBind -v
```

Expected: `BindIdentityInput` / `BindExternalIdentity` 未定义。

- [ ] **Step 3: 实现**

`internal/domain/user/external_login.go` 末尾加:

```go
// BindIdentityInput carries an already-authenticated external identity plus the
// logged-in local user it should attach to. Unlike ExternalLoginInput there are
// no auto-provision knobs: the caller is signed in, so there is nothing to
// provision.
type BindIdentityInput struct {
	TenantID     int64
	UserID       int64
	ProviderType string
	ProviderID   string
	ExternalID   string
	DisplayName  string
	Raw          map[string]any
}

// BindExternalIdentity attaches an external account to an existing local user.
// The caller must already have completed the IdP's authentication — that is what
// proves they hold the external account. This function decides only who holds it
// locally:
//
//	free                     → create the binding
//	held by a live user      → refuse; taking it would move that user's login
//	held by a deleted user   → take over; no live person loses an identity, and
//	                           this is the only way back for an account whose
//	                           binding went down with a deleted shell profile
func (s *Service) BindExternalIdentity(ctx context.Context, in *BindIdentityInput) error {
	if in == nil || in.ExternalID == "" || in.UserID == 0 {
		return fmt.Errorf("user id and external id required")
	}

	existing, err := s.repo.GetAnyIdentityByExternal(ctx, in.TenantID, in.ProviderType, in.ProviderID, in.ExternalID)
	switch {
	case err == nil && existing != nil:
		if existing.UserID == in.UserID && !existing.DeletedAt.Valid {
			return nil // already bound to this very user; idempotent
		}
		if !existing.DeletedAt.Valid {
			// A live binding. Is its owner still around?
			if _, uerr := s.repo.GetByID(ctx, existing.UserID); uerr == nil {
				return ErrExternalIDTaken
			}
			if !dberr.IsNotFound(uerr) {
				return fmt.Errorf("check binding owner: %w", uerr)
			}
			// Owner is deleted — fall through to takeover.
		}
		return s.takeOverIdentity(ctx, existing, in)
	case err != nil && !dberr.IsNotFound(err):
		return fmt.Errorf("lookup identity: %w", err)
	}

	now := time.Now()
	name := in.DisplayName
	identity := &UserIdentity{
		ID:           s.idGen.Generate(),
		UserID:       in.UserID,
		TenantID:     in.TenantID,
		ProviderType: in.ProviderType,
		ProviderID:   in.ProviderID,
		ExternalID:   in.ExternalID,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if name != "" {
		identity.ExternalName = &name
	}
	if err := s.repo.CreateIdentity(ctx, identity); err != nil {
		return fmt.Errorf("create identity: %w", err)
	}
	s.eventBus.Publish(ctx, event.Event{
		Type:    event.UserUpdated,
		Payload: map[string]any{"user_id": in.UserID, "action": "identity_bound", "provider": in.ProviderType},
	})
	return nil
}

// takeOverIdentity moves a binding whose previous owner was deleted onto the
// caller. Audited as its own action: it is the one path where an external
// identity changes hands.
func (s *Service) takeOverIdentity(ctx context.Context, existing *UserIdentity, in *BindIdentityInput) error {
	prevOwner := existing.UserID
	existing.UserID = in.UserID
	existing.UpdatedAt = time.Now()
	if in.DisplayName != "" {
		name := in.DisplayName
		existing.ExternalName = &name
	}
	if err := s.repo.RestoreIdentityTo(ctx, existing); err != nil {
		return fmt.Errorf("take over identity: %w", err)
	}
	s.eventBus.Publish(ctx, event.Event{
		Type: event.UserUpdated,
		Payload: map[string]any{
			"user_id": in.UserID, "action": "identity_taken_over",
			"provider": in.ProviderType, "previous_user_id": prevOwner,
		},
	})
	return nil
}
```

`RestoreIdentityTo` 是新的 repo 方法(清 `deleted_at` + 改 `user_id` + 更新时间戳,`Unscoped()`),加到 `repository.go` / `repository_impl.go`:

```go
// RestoreIdentityTo moves a binding to a new owner and clears deleted_at.
func (r *gormRepository) RestoreIdentityTo(ctx context.Context, i *UserIdentity) error {
	err := r.db.WithContext(ctx).
		Unscoped().
		Model(&UserIdentity{}).
		Where("id = ?", i.ID).
		Updates(map[string]any{
			"user_id":       i.UserID,
			"external_name": i.ExternalName,
			"deleted_at":    nil,
			"updated_at":    i.UpdatedAt,
		}).Error
	if err != nil {
		return fmt.Errorf("restore identity to new owner: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: 跑测试**

```bash
go test ./internal/domain/user/... -v
go build ./... && go vet ./...
```

Expected: 三条 bind 测试 PASS,既有测试不回归。

- [ ] **Step 5: 暂存并报告**

```bash
git add -A && git status --short
```

## Task 13: seam 接线

**Files:**
- Modify: `pkg/ee/registry/seam.go`
- Modify: `app/adapters_user.go`
- Modify: `mxid-ee/features/externalidp/register.go`

**Interfaces:**
- Consumes: Task 12 的 `Service.BindExternalIdentity`
- Produces: `registry.BindIdentityInput`、`registry.BindIdentityFunc`,以及 `InitContext` 上的 `BindIdentity` 字段

- [ ] **Step 1: seam 类型**

`pkg/ee/registry/seam.go`,紧挨 `ExternalLoginFunc`(`:43`)加:

```go
// BindIdentityInput is the neutral binding contract between an external IdP
// callback (EE) and the CE user domain. Mirrors ResolverInput but carries the
// already-authenticated local user instead of auto-provision knobs.
type BindIdentityInput struct {
	TenantID     int64
	UserID       int64
	ProviderType string
	ProviderID   string
	ExternalID   string
	DisplayName  string
	Raw          map[string]any
}

// BindIdentityFunc links an already-authenticated external identity to an
// existing local user. Implemented by the CE user domain. Account linking is a
// CE concern on purpose: the rule deciding who may take over an external
// identity is a security decision and belongs in auditable open code, not in an
// obfuscated EE build.
type BindIdentityFunc func(ctx context.Context, in *BindIdentityInput) error
```

在 `InitContext` 结构体里加字段 `BindIdentity BindIdentityFunc`(照抄它旁边 `ExternalLogin` 字段的写法与 exhaustruct 要求)。

- [ ] **Step 2: CE 适配器**

`app/adapters_user.go`,照 `:29` 附近既有的 resolver 适配写法加一个:

```go
// bindIdentityAdapter maps the neutral EE seam type onto the CE user service.
func bindIdentityAdapter(svc *user.Service) registry.BindIdentityFunc {
	return func(ctx context.Context, in *registry.BindIdentityInput) error {
		return svc.BindExternalIdentity(ctx, &user.BindIdentityInput{
			TenantID:     in.TenantID,
			UserID:       in.UserID,
			ProviderType: in.ProviderType,
			ProviderID:   in.ProviderID,
			ExternalID:   in.ExternalID,
			DisplayName:  in.DisplayName,
			Raw:          in.Raw,
		})
	}
}
```

在 `app/run.go` 填充 `InitContext` 的地方加上 `BindIdentity: bindIdentityAdapter(userSvc),`。仓库对 wiring 结构体有 `exhaustruct` 守卫,漏填会在构建期被抓到。

- [ ] **Step 3: 验证**

```bash
go build ./... && go vet ./...
go test ./app/...
cd /Users/kerbos/Workspaces/project/mxid/mxid-ee && go build ./...
```

Expected: CE 与 EE 都编译通过。EE 此时尚未使用新 seam,只需保证不破坏编译。

- [ ] **Step 4: 暂存并报告**

```bash
git add -A && git status --short
```

## Task 14: EE —— state 加绑定意图

**Files:**
- Modify: `mxid-ee/features/externalidp/service.go:513-600`(`stateEntry` / `StartLogin` / `FinishLogin`)

**Interfaces:**
- Consumes: 现有 `stateEntry`、`s.rdb`、`generateState()`
- Produces:
  - `stateEntry.BindUserID int64`
  - `Service.StartBind(ctx context.Context, tenantID int64, code, redirectURI, finalReturnURL string, bindUserID int64) (string, error)`
  - `FinishLogin` 的返回增加 `bindUserID int64`

- [ ] **Step 1: state 加字段**

`stateEntry` 结构体加:

```go
	// BindUserID is non-zero when this flow was started by a signed-in user
	// attaching an external account to their own profile, rather than by an
	// anonymous visitor signing in. The callback must never take it from the
	// query string — it is pinned here at start time and read back from Redis.
	BindUserID int64 `json:"bind_user_id,omitempty"`
```

- [ ] **Step 2: StartLogin 抽出公共实现**

把 `StartLogin` 的主体抽成私有 `start(ctx, tenantID, code, redirectURI, finalReturnURL string, bindUserID int64) (string, error)`,`StartLogin` 传 `0`,新增:

```go
// StartBind begins an authorization round-trip whose result attaches the
// external account to bindUserID instead of signing somebody in.
func (s *Service) StartBind(ctx context.Context, tenantID int64, code, redirectURI, finalReturnURL string, bindUserID int64) (string, error) {
	if bindUserID == 0 {
		return "", fmt.Errorf("bind user id required")
	}
	return s.start(ctx, tenantID, code, redirectURI, finalReturnURL, bindUserID)
}
```

`entry := stateEntry{...}` 里带上 `BindUserID: bindUserID`。

- [ ] **Step 3: FinishLogin 回传意图**

签名改为:

```go
func (s *Service) FinishLogin(ctx context.Context, state, code string) (*ExternalIDP, *ExternalIdentity, string, int64, error)
```

新增的 `int64` 是 `entry.BindUserID`。所有 return 语句补上对应值(登录流程返回 `0`)。更新全部调用点 —— `grep -rn "FinishLogin(" mxid-ee/` 找齐。

- [ ] **Step 4: 验证**

```bash
cd /Users/kerbos/Workspaces/project/mxid/mxid-ee && go build ./... && go vet ./... && go test ./...
```

Expected: 编译通过,既有 EE 测试全绿(`external_login_flow_test.go` / `mfa_challenge_test.go` 会覆盖 `FinishLogin` 的调用)。

- [ ] **Step 5: 暂存并报告**

```bash
cd /Users/kerbos/Workspaces/project/mxid/mxid-ee && git add -A && git status --short
```

## Task 15: EE —— portal 绑定路由

**Files:**
- Modify: `mxid-ee/features/externalidp/portal_handler.go`
- Modify: `mxid-ee/features/externalidp/register.go`

**Interfaces:**
- Consumes: Task 13 的 `registry.BindIdentityFunc`;Task 14 的 `StartBind` / `FinishLogin`
- Produces: `POST /api/v1/portal/security/identities/bind/:idpCode`

**安全要点:** 回调里的 `BindUserID` 只能来自 Redis 中的 state,**绝不**从查询串取。且必须与当前 portal 会话的用户一致,否则拒绝 —— 否则任何人诱导目标点开一个链接就能把自己的外部账号绑到目标账号上。

- [ ] **Step 1: 加 bind 起始路由**

`portal_handler.go` 加(注意这条挂在**已认证**的 portal 组,不是 `portal-public`):

```go
// startBind kicks off an authorization round-trip that ends in attaching the
// external account to the signed-in user. Unlike login, this route requires a
// session — the whole point is that we already know who the caller is.
func (h *PortalHandler) startBind(c *gin.Context) {
	userID := c.GetInt64(authn.CtxUserID)
	tenantID := c.GetInt64(authn.CtxTenantID)
	if userID == 0 {
		response.Unauthorized(c, errcode.NumUnauthenticated, "sign in required")
		return
	}
	if !h.stepUpFresh(c) {
		response.Forbidden(c, authn.CodeStepUpRequired, "recent MFA required to bind an external account")
		return
	}

	idpCode := c.Param("idpCode")
	redirectURI := h.callbackURL(c.Request.Context(), tenantID)
	authURL, err := h.svc.StartBind(c.Request.Context(), tenantID, idpCode, redirectURI, h.frontendOrigin(c.Request.Context())+"/security", userID)
	if err != nil {
		response.InternalError(c, "start bind failed", err)
		return
	}
	response.OK(c, gin.H{"authorize_url": authURL})
}
```

具体的 `CtxUserID` / `callbackURL` / step-up helper 名称照抄同文件与 `internal/gateway/portal/security_handler.go:241` 的既有写法 —— 若 EE 侧没有 step-up helper,通过 `InitContext` 从 CE 注入一个,不要在 EE 里另起一套时效逻辑(portal 与 console 的 sudo 窗口必须一致)。

响应返回授权 URL 由前端跳转,不用服务端 302 —— 这条是 POST,浏览器不该跟随重定向。

- [ ] **Step 2: 回调分流**

`callback`(`:283`)改为接收新的返回值,并在识别出绑定意图时走绑定分支:

```go
	idp, identity, finalURL, bindUserID, err := h.svc.FinishLogin(c.Request.Context(), state, cbCode)
	if err != nil {
		c.Redirect(http.StatusFound, h.failureRedirect(c.Request.Context())+"&reason="+url.QueryEscape(err.Error()))
		return
	}

	if bindUserID > 0 {
		// A binding round-trip, not a sign-in. The user id comes from the state
		// entry we wrote at start time — never from the query string — and must
		// still match the live session, or a link sent to a victim could attach
		// the attacker's external account to the victim's profile.
		sessUserID := c.GetInt64(authn.CtxUserID)
		if sessUserID == 0 || sessUserID != bindUserID {
			c.Redirect(http.StatusFound, h.failureRedirect(c.Request.Context())+"&reason=bind_session_mismatch")
			return
		}
		berr := h.bindIdentity(c.Request.Context(), &registry.BindIdentityInput{
			TenantID:     idp.TenantID,
			UserID:       bindUserID,
			ProviderType: identity.ProviderType,
			ProviderID:   identity.ProviderID,
			ExternalID:   identity.ExternalID,
			DisplayName:  identity.DisplayName,
			Raw:          identity.Raw,
		})
		if berr != nil {
			c.Redirect(http.StatusFound, h.failureRedirect(c.Request.Context())+"&reason="+url.QueryEscape(berr.Error()))
			return
		}
		c.Redirect(http.StatusFound, finalURL+"?bind=ok")
		return
	}
```

`h.bindIdentity` 是从 `InitContext.BindIdentity` 注入到 `PortalHandler` 上的字段,在 `register.go` 构造 handler 时填入。

**注意回调路由的认证状态。** 现有 callback 挂在 `portal-public`(未认证组),`c.GetInt64(authn.CtxUserID)` 在那里恒为 0。
仓库**没有**可选会话中间件(已确认:`internal/domain/authn/middleware.go` 只有强制的 `AuthMiddleware`),需要新增。

考虑过改让绑定用一条独立的已认证回调路由,否决了 —— 那需要客户在 Lark/IdP 后台把新的
`redirect_uri` 加进白名单,给每个已部署的租户平添一次运维动作。复用现有回调、加一层可选解析更划算。

新增 `internal/domain/authn/optional_session.go`:

```go
package authn

import (
	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/pkg/session"
)

// OptionalAuthMiddleware resolves the session cookie when one is present and
// valid, and does nothing when it is not. It never rejects.
//
// This exists for the external-IdP callback, which serves two flows through one
// URL: an anonymous visitor signing in, and a signed-in user attaching an
// external account to their profile. The second needs to know who is calling;
// the first must not be blocked. Deliberately does NOT Touch the session —
// touching here would let a callback keep an idle session alive, which is
// exactly what AuthMiddleware's comment warns against.
func OptionalAuthMiddleware(sessionMgr *session.Manager, namespace string) gin.HandlerFunc {
	cookieName := cookieForNamespace(namespace)

	return func(c *gin.Context) {
		if cookieName == "" {
			c.Next()
			return
		}
		sessionID, err := c.Cookie(cookieName)
		if err != nil || sessionID == "" {
			c.Next()
			return
		}
		sess, err := sessionMgr.Get(c.Request.Context(), namespace, sessionID)
		if err != nil || sess == nil {
			c.Next()
			return
		}
		c.Set(CtxUserID, sess.UserID)
		c.Set(CtxTenantID, sess.TenantID)
		c.Set(CtxSessionID, sess.ID)
		c.Set(CtxNamespace, namespace)
		c.Next()
	}
}
```

在 `register.go` 里**只**把它挂到 callback 这一条路由上,不要挂到整个 `portal-public` 组 ——
该组还有登录起始等路由,给它们注入会话没有意义,而且仓库踩过 `.Use` 只作用于其后注册路由的坑,
逐路由挂载可以完全绕开顺序问题:

```go
	portalGroup.GET("/external-idp/callback",
		authn.OptionalAuthMiddleware(app.SessionMgr, session.NamespacePortal),
		ph.callback)
```

回调路由的实际路径与 handler 名照抄 `register.go:85` 附近既有的 `RegisterRoutes` 注册。

- [ ] **Step 3: 注册路由**

`register.go` 的 `initFeature` 里,把 bind 起始路由挂到已认证的 portal 安全组,并把 `ic.BindIdentity` 传给 `PortalHandler`:

```go
	securityGroup := app.PortalGroup.Group("/security")
	securityGroup.POST("/identities/bind/:idpCode", ph.startBind)
```

具体的 portal 已认证组变量名照抄 `register.go:63` 附近对 `portal-public` 的处理,取其对应的已认证组。

- [ ] **Step 4: 验证**

```bash
cd /Users/kerbos/Workspaces/project/mxid/mxid-ee && go build ./... && go vet ./... && go test ./...
```

再起 EE dev 栈(`make dev-up EE=1`)用 curl 确认:

```bash
curl -i -X POST http://localhost:3500/api/v1/portal/security/identities/bind/lark
```

Expected: 401(未认证),不是 404。

- [ ] **Step 5: 暂存并报告**

```bash
cd /Users/kerbos/Workspaces/project/mxid/mxid-ee && git add -A && git status --short
```

## Task 16: portal 前端 —— 绑定按钮

**Files:**
- Modify: `web/packages/shared/src/api/portal.ts`
- Modify: `web/apps/portal/src/pages/security/index.tsx`
- Modify: i18n 两份
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: Task 15 的 `POST /portal/security/identities/bind/:idpCode`
- Produces: 无

- [ ] **Step 1: API 方法**

`web/packages/shared/src/api/portal.ts` 加:

```ts
  startIdentityBind: (idpCode: string) =>
    client.post<ApiResponse<{ authorize_url: string }>>(
      `/security/identities/bind/${encodeURIComponent(idpCode)}`,
    ).then((r) => r.data.data),
```

同文件还需要一个取可用外部 IdP 列表的方法 —— 若已存在(登录页用它渲染第三方按钮)直接复用,不要新增重复端点。

- [ ] **Step 2: 安全页加绑定区**

`web/apps/portal/src/pages/security/index.tsx` 的身份绑定区:已绑定的照旧列出;未绑定的 IdP 每个给一个 `绑定` 按钮:

```tsx
  const handleBind = async (idpCode: string) => {
    setBinding(idpCode)
    try {
      const res = await portalApi.startIdentityBind(idpCode)
      window.location.href = res.authorize_url
    } catch (e) {
      toast.error(t('security.identities.bindFailed'), extractMessage(e))
      setBinding(null)
    }
  }
```

成功路径是整页跳转,没有成功 toast 的时机 —— 回来时 URL 带 `?bind=ok`,在页面挂载时读一次并给 `toast.success`,读完把该参数从 URL 清掉,免得刷新重复提示:

```tsx
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    if (params.get('bind') === 'ok') {
      toast.success(t('security.identities.bindSuccess'))
      params.delete('bind')
      const qs = params.toString()
      window.history.replaceState({}, '', window.location.pathname + (qs ? `?${qs}` : ''))
    }
  }, [t])
```

- [ ] **Step 3: i18n**

`zh-CN.ts`:

```ts
        bind: '绑定',
        bindSuccess: '绑定成功',
        bindFailed: '绑定失败',
        bindHint: '绑定后可用该账号直接登录。',
```

`en-US.ts` 镜像。另外为 Task 4 的三个错误码在 `toast.tsx` 的错误处理里补上可读文案(按码分支,用 `CODE_*` 常量而非数字字面量),尤其 `NumExternalIDTaken` 要说清"该账号已绑定到其他用户"。

- [ ] **Step 4: 构建 + 端到端**

```bash
cd web && pnpm -r build
make dev-up EE=1
```

端到端走一遍,这也是恢复用户 H 的排练:

1. 控制台给一个"仅外部登录"用户设临时密码
2. 该用户用账号密码登 portal(若强制 MFA,先绑 TOTP)
3. 安全页点 `绑定 Lark` → OAuth → 回来看到成功 toast
4. 登出,用 Lark 登录 → 进的是原账号,不是新建的空壳

- [ ] **Step 5: CHANGELOG + 暂存**

`### Added`:

```markdown
- Users can bind an external identity provider account to their existing profile from the
  portal security page. Completing the provider's own sign-in is what proves they hold the
  external account, so recovering a lost binding never requires an administrator to type an
  `external_id` by hand. An external account still held by a live user is refused; one left
  behind by a deleted account is taken over and audited.
```

```bash
git add -A && git status --short
cd /Users/kerbos/Workspaces/project/mxid/mxid-ee && git add -A && git status --short
```

**Phase D 完成 —— 全部交付。**

---

# 收尾

## Task 17: 文档与复盘

**Files:**
- Modify: `docs/ARCHITECTURE.md`
- Create: `docs/postmortems/2026-08-10-mfa-reset-identity-unbind-lockout.md`
- Move: `docs/2026-08-10-identity-rebind-and-204-envelope-design.md` → `docs/archive/`

- [ ] **Step 1: ARCHITECTURE.md**

在"Invariants enforced by tests"一节加一条:handler 不得返回 204,由 `internal/httpguard` 守卫;
在描述 EE seam 的位置补上 `BindIdentityFunc`,与 `ExternalLoginFunc` 并列。

- [ ] **Step 2: 写复盘**

`docs/postmortems/2026-08-10-mfa-reset-identity-unbind-lockout.md`,照 `2026-07-06-audit-jsonb-verify-failure.md` 的结构写。核心要写进去的东西:

- 一个纯 UI 层的信封不匹配,如何一路升级成用户永久失去登录能力
- 操作者两次收到"删除失败"而操作其实成功,这是所有后续误判的起点
- 软删与 `ON DELETE CASCADE` 的语义错配(UPDATE 不触发 CASCADE)
- 单向门:系统能删除一个东西,却没有任何路径把它建回来
- 检测手段:五处 204 在代码里躺了很久,没有任何测试或告警指出它们

- [ ] **Step 3: 归档设计文档**

```bash
git mv docs/2026-08-10-identity-rebind-and-204-envelope-design.md docs/archive/
```

- [ ] **Step 4: 暂存并报告**

```bash
git add -A && git status --short
```

## Task 18: 发版前全量验证

- [ ] **Step 1: 后端全量**

```bash
go build ./... && go vet ./...
go test ./...
golangci-lint --version   # 必须是 v1.64.8
golangci-lint run
```

- [ ] **Step 2: EE 全量**

```bash
cd /Users/kerbos/Workspaces/project/mxid/mxid-ee && go build ./... && go vet ./... && go test ./...
```

- [ ] **Step 3: 前端全量**

```bash
cd web && pnpm -r build
```

- [ ] **Step 4: 迁移往返**

```bash
make migrate-up
make migrate-down && make migrate-down   # 退掉 000069 与 000068
make migrate-up
```

Expected: 往返无错。`down` 会物理删除软删行,只在 dev 库上做。

- [ ] **Step 5: 报告**

汇总:改了哪些文件、跑了哪些验证、哪些是实测通过的、哪些只有 CI 能验。**不要**在未跑通验证的情况下报告完成。等用户指示再 commit 与发版(CE 与 EE 锁步同 tag,先推 CE)。
