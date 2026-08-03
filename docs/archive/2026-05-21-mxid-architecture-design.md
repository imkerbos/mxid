# MXID Architecture Design Specification

> Open-source Enterprise Identity and Access Management (IAM/SSO) Platform
>
> Version: 1.0.0 | Date: 2026-05-21 | License: AGPL v3.0

## 1. Overview

MXID is an open-source enterprise IAM/SSO platform (community edition) targeting commercial-level quality. Benchmarks: TopIAM, Okta, Keycloak, MaxKey, 竹云IDaaS.

### 1.1 Goals

- Multi-protocol SSO: OIDC, SAML 2.0, CAS 3.0, JWT, FORM
- Organization/department management with tree hierarchy
- RBAC permission engine (Casbin)
- Application and application group management
- Multi-factor authentication (TOTP, SMS, Email)
- Identity source synchronization (LDAP, DingTalk, Feishu, etc.)
- Full audit logging
- Enterprise-grade performance and stability

### 1.2 Deployment Model

Private deployment first (community open-source). Enterprise edition in future.

### 1.3 License

AGPL v3.0

---

## 2. Architecture

### 2.1 Pattern: Modular Monolith

Single Go binary. Internally organized by domain modules with clear boundaries. Modules communicate via Go interfaces (direct call) and an in-process event bus (loose coupling).

**Why modular monolith:**
- Single binary deployment (Go's strength)
- Shared database transactions (IAM consistency critical)
- Lower operational complexity than microservices
- Clear module boundaries allow future microservice extraction
- Proven pattern: Keycloak (Java monolith), Casdoor (Go monolith)

### 2.2 System Architecture

```
┌─────────────────────────────────────────────────────┐
│                    MXID Server                       │
│                 (Single Go Binary)                   │
│                                                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐            │
│  │ Console  │ │  Portal  │ │ OpenAPI  │  ← HTTP     │
│  │ (Admin)  │ │ (User)   │ │(3rd-party)│   Routes   │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘            │
│       │             │            │                   │
│  ┌────┴─────────────┴────────────┴─────┐            │
│  │         Shared Middleware            │            │
│  │  (Auth, RBAC, Audit, RateLimit,     │            │
│  │   Tenant, CORS, RequestID)          │            │
│  └────┬─────────────┬──────────────────┘            │
│       │             │                                │
│  ┌────┴─────┐  ┌────┴──────┐  ┌──────────┐         │
│  │ Domain   │  │ Protocol  │  │ Infra    │         │
│  │ Modules  │  │ Engine    │  │ Modules  │         │
│  │          │  │           │  │          │         │
│  │ • user   │  │ • oidc    │  │ • audit  │         │
│  │ • org    │  │ • saml    │  │ • event  │         │
│  │ • app    │  │ • cas     │  │ • cache  │         │
│  │ • authn  │  │ • jwt     │  │ • mfa    │         │
│  │ • perm   │  │ • form    │  │ • notify │         │
│  │ • group  │  │           │  │ • crypto │         │
│  └────┬─────┘  └────┬──────┘  │ • storage│         │
│       │             │         └────┬─────┘         │
│  ┌────┴─────────────┴───────────────┴─────┐         │
│  │              Data Layer                 │         │
│  │    GORM + PostgreSQL + Redis            │         │
│  └─────────────────────────────────────────┘         │
└─────────────────────────────────────────────────────┘

┌──────────────┐  ┌──────────────┐
│ Console SPA  │  │  Portal SPA  │  ← Standalone frontends
│ React+Shadcn │  │ React+Shadcn │    Embedded in binary or separate
└──────────────┘  └──────────────┘
```

### 2.3 Tech Stack

| Layer | Choice | Reason |
|-------|--------|--------|
| Language | Go 1.25+ | Performance, single binary, team familiarity |
| HTTP Framework | Gin | Team standard across all projects |
| ORM | GORM | Team standard, PG support |
| Database | PostgreSQL 16 | JSONB, ltree, RLS, complex query strength |
| Cache/Session | Redis 7 | Session storage, distributed locks, rate limiting |
| Config | Viper | Team standard |
| Logging | Zap | Team standard |
| DB Migration | golang-migrate | Proven in cdn-scheduler (92 migrations) |
| Auth Token | golang-jwt/jwt | Team standard |
| Permission | Casbin | Go-native RBAC/ABAC, GORM adapter |
| Event Bus | In-process EventBus | Module decoupling, replaceable with MQ later |
| Cron | robfig/cron | Password expiry checks, sync jobs |
| OIDC | go-oidc + oauth2 | Standard library |
| SAML | crewjam/saml | Best Go SAML implementation |
| Frontend | React 18 + Vite | Modern build tooling |
| UI Components | Shadcn/ui + TailwindCSS | Tech-style, fully customizable |
| Animation | Framer Motion | Professional transition animations |
| State Mgmt | Zustand | Lightweight React state |
| API Spec | RESTful + OpenAPI 3.0 | Standardized documentation |

### 2.4 Ports

| Service | Dev Port | Prod Port |
|---------|----------|-----------|
| MXID Backend | 10050 | 8080 (behind gateway) |
| Console Frontend (Vite) | 3500 | — (static, served by Nginx) |
| Portal Frontend (Vite) | 3501 | — (static, served by Nginx) |
| Nginx/Gateway | — | 80/443 |

Existing allocated ports (do not use):

| Project | Ports |
|---------|-------|
| mxsec-platform | 3000, 8080, 6751 |
| k8sinsight | 30010, 10080 |
| cdn-scheduler | 3600, 10090 |
| ticketdesk | 3100, 10010 |
| acme-console | 3200, 10020 |
| mxsecstrike | 3700, 10080 |
| mxcmdb | 3800, 10030 |

---

## 3. Project Structure

```
mxid/
├── cmd/
│   └── server/
│       └── main.go                 # Single entry point
│
├── internal/
│   ├── domain/                      # Business domain modules
│   │   ├── user/                    # User management
│   │   │   ├── handler.go
│   │   │   ├── service.go
│   │   │   ├── repository.go       # Interface
│   │   │   ├── repository_impl.go  # GORM implementation
│   │   │   ├── model.go            # Domain models
│   │   │   └── dto.go              # Request/response structs
│   │   │
│   │   ├── org/                     # Organization/department
│   │   ├── group/                   # User groups
│   │   ├── app/                     # Application + app groups
│   │   ├── authn/                   # Authentication engine
│   │   │   ├── local/              #   Username/password
│   │   │   ├── sms/                #   SMS OTP
│   │   │   ├── email/              #   Email OTP
│   │   │   ├── totp/               #   TOTP
│   │   │   ├── webauthn/           #   WebAuthn/FIDO2 (P2)
│   │   │   ├── social/             #   Social login (P1)
│   │   │   │   ├── github.go
│   │   │   │   ├── dingtalk.go
│   │   │   │   ├── feishu.go
│   │   │   │   ├── wechat.go
│   │   │   │   └── ...
│   │   │   └── ldap/               #   LDAP/AD (P1)
│   │   │
│   │   ├── permission/              # Permission engine (Casbin)
│   │   │   ├── rbac/
│   │   │   ├── policy/
│   │   │   └── enforcer.go
│   │   │
│   │   ├── approval/                # Approval workflow (P2, dir reserved)
│   │   └── audit/                   # Audit logging
│   │
│   ├── connector/                   # Identity source sync (worker)
│   │   ├── ldap/                    # P1
│   │   ├── scim/                    # P2
│   │   ├── dingtalk/                # P2
│   │   ├── feishu/                  # P2
│   │   └── wechatwork/             # P2
│   │
│   ├── protocol/                    # SSO protocol engine
│   │   ├── oidc/
│   │   ├── saml/
│   │   ├── cas/
│   │   ├── jwt/                     # P1
│   │   ├── form/                    # P1
│   │   └── resolver/               # Protocol-layer adapters
│   │       ├── identity.go          #   User identity resolution
│   │       ├── app.go               #   App config resolution
│   │       └── session.go           #   SSO session context
│   │
│   ├── gateway/                     # Route group registration
│   │   ├── console/                 # /api/console/*
│   │   ├── portal/                  # /api/portal/*
│   │   └── openapi/                 # /api/v1/*
│   │
│   ├── middleware/                   # Shared middleware
│   │   ├── auth.go                  #   JWT authentication
│   │   ├── rbac.go                  #   Permission check
│   │   ├── tenant.go                #   Tenant context injection
│   │   ├── audit.go                 #   Audit log interception
│   │   ├── ratelimit.go             #   Rate limiting
│   │   ├── cors.go                  #   CORS
│   │   └── requestid.go             #   Request tracing
│   │
│   └── bootstrap/                   # Startup orchestration
│       ├── app.go                   #   Module registration + DI
│       ├── database.go              #   DB init
│       ├── cache.go                 #   Redis init
│       ├── router.go                #   Route aggregation
│       └── migration.go             #   Auto migration
│
├── pkg/                             # Public reusable packages
│   ├── crypto/                      # AES/RSA/Hash
│   ├── event/                       # In-process event bus
│   ├── session/                     # Redis-backed session management
│   ├── notify/                      # Email/SMS
│   ├── storage/                     # File storage abstraction (local/S3/OSS)
│   ├── geoip/                       # IP geolocation
│   ├── httputil/                    # HTTP utilities
│   └── pagination/                  # Pagination helpers
│
├── migrations/                      # SQL migration files
│   ├── 000001_init_tenant.up.sql
│   ├── 000001_init_tenant.down.sql
│   ├── 000002_init_user.up.sql
│   └── ...
│
├── configs/
│   ├── config.yaml                  # Main config
│   ├── config.dev.yaml              # Dev overrides
│   └── config.prod.yaml             # Prod overrides
│
├── web/                             # Frontend monorepo
│   ├── pnpm-workspace.yaml
│   ├── package.json
│   ├── tailwind.config.ts
│   ├── tsconfig.base.json
│   ├── packages/
│   │   └── ui/                      # Shared UI library
│   │       ├── package.json
│   │       └── src/
│   │           ├── components/
│   │           ├── layouts/
│   │           ├── hooks/
│   │           ├── lib/
│   │           └── styles/
│   └── apps/
│       ├── console/                 # Admin console SPA
│       └── portal/                  # User portal SPA
│
├── deploy/
│   ├── dockerfile/
│   │   └── Dockerfile
│   ├── compose/
│   │   └── docker-compose.yml
│   ├── nginx/
│   │   └── nginx.conf
│   └── scripts/
│       └── init-db.sh
│
├── docs/
├── go.mod
├── go.sum
├── Makefile
├── .air.toml
└── README.md
```

### 3.1 Module Responsibilities

| Module | Responsibility | Exposed Interface | Dependencies |
|--------|---------------|-------------------|--------------|
| user | User CRUD, password policy, status, profile | `UserService` | tenant (field only) |
| org | Org tree/dept CRUD, member management (PG ltree) | `OrgService` | user |
| group | User group CRUD, member management | `GroupService` | user |
| app | App CRUD, app groups, access policy, protocol config | `AppService` | permission |
| authn | Authentication engine: unified multi-method interface | `AuthnProvider` | user |
| permission | Casbin RBAC/ABAC, role/policy management | `Enforcer` | — |
| audit | Audit log write, query, statistics | `AuditService` | — |
| connector | Identity source config, sync scheduling | `SyncService` | user, org |
| protocol | OIDC/SAML/CAS/JWT/FORM protocol handling | HTTP endpoints | resolver |
| resolver | Protocol-layer adapter (abstracts business services) | `AppResolver`, `IdentityResolver`, `SessionResolver` | app, user, authn |

### 3.2 Module Communication Rules

1. **Direct call**: Modules call each other via Go interfaces (in-process, zero overhead)
2. **Event bus**: Cross-module side effects go through events (e.g., user created → audit record, notification)
3. **No circular deps**: Dependency direction is one-way

Dependency direction:
```
protocol → resolver → app, user, authn
authn → user (direct), user → authn (event bus only)
org → user
group → user
connector → user, org
audit ← (event bus) ← all modules
```

---

## 4. Data Model

### 4.1 Conventions

- Primary key: `id BIGINT` (snowflake algorithm, not auto-increment)
- Multi-tenant: `tenant_id BIGINT` (reserved, MVP uses default value)
- Soft delete: `deleted_at TIMESTAMPTZ NULL`
- Audit fields: `created_at`, `updated_at TIMESTAMPTZ`
- Creator/updater: `created_by`, `updated_by BIGINT`
- Table prefix: `mxid_`

### 4.2 Tenant (MVP lightweight)

```sql
CREATE TABLE mxid_tenant (
    id          BIGINT PRIMARY KEY,
    name        VARCHAR(128) NOT NULL,
    code        VARCHAR(64)  NOT NULL UNIQUE,
    status      SMALLINT     NOT NULL DEFAULT 1,    -- 1=enabled 0=disabled
    config      JSONB        DEFAULT '{}',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ
);
```

### 4.3 User Domain

```sql
CREATE TABLE mxid_user (
    id              BIGINT PRIMARY KEY,
    tenant_id       BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    username        VARCHAR(128) NOT NULL,
    email           VARCHAR(256),
    phone           VARCHAR(32),
    display_name    VARCHAR(128),
    avatar          VARCHAR(512),
    password_hash   VARCHAR(256),
    status          SMALLINT     NOT NULL DEFAULT 1,  -- 1=active 2=locked 3=disabled 4=pending
    last_login_at   TIMESTAMPTZ,
    last_login_ip   VARCHAR(64),
    password_changed_at TIMESTAMPTZ,
    must_change_pwd BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_by      BIGINT,
    updated_by      BIGINT,
    deleted_at      TIMESTAMPTZ,
    UNIQUE(tenant_id, username),
    UNIQUE(tenant_id, email),
    UNIQUE(tenant_id, phone)
);

CREATE TABLE mxid_user_detail (
    id          BIGINT PRIMARY KEY,
    user_id     BIGINT       NOT NULL REFERENCES mxid_user(id),
    gender      SMALLINT,
    birthday    DATE,
    address     VARCHAR(512),
    employee_no VARCHAR(64),
    job_title   VARCHAR(128),
    department  VARCHAR(256),
    extra       JSONB        DEFAULT '{}',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE mxid_user_password_history (
    id            BIGINT PRIMARY KEY,
    user_id       BIGINT       NOT NULL REFERENCES mxid_user(id),
    password_hash VARCHAR(256) NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_pwd_history_user ON mxid_user_password_history(user_id);

CREATE TABLE mxid_user_identity (
    id              BIGINT PRIMARY KEY,
    user_id         BIGINT       NOT NULL REFERENCES mxid_user(id),
    tenant_id       BIGINT       NOT NULL,
    provider_type   VARCHAR(32)  NOT NULL,
    provider_id     VARCHAR(128) NOT NULL,
    external_id     VARCHAR(256) NOT NULL,
    external_name   VARCHAR(256),
    extra           JSONB        DEFAULT '{}',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, provider_type, external_id)
);
```

### 4.4 Organization Domain

```sql
CREATE EXTENSION IF NOT EXISTS ltree;

CREATE TABLE mxid_organization (
    id          BIGINT PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    name        VARCHAR(128) NOT NULL,
    code        VARCHAR(64)  NOT NULL,
    parent_id   BIGINT       REFERENCES mxid_organization(id),
    path        LTREE        NOT NULL,
    sort_order  INT          NOT NULL DEFAULT 0,
    status      SMALLINT     NOT NULL DEFAULT 1,
    extra       JSONB        DEFAULT '{}',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_by  BIGINT,
    updated_by  BIGINT,
    deleted_at  TIMESTAMPTZ,
    UNIQUE(tenant_id, code)
);
CREATE INDEX idx_org_path ON mxid_organization USING GIST(path);
CREATE INDEX idx_org_parent ON mxid_organization(parent_id);

CREATE TABLE mxid_user_org (
    id          BIGINT PRIMARY KEY,
    user_id     BIGINT   NOT NULL REFERENCES mxid_user(id),
    org_id      BIGINT   NOT NULL REFERENCES mxid_organization(id),
    is_primary  BOOLEAN  NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, org_id)
);

CREATE TABLE mxid_user_group (
    id          BIGINT PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    name        VARCHAR(128) NOT NULL,
    code        VARCHAR(64)  NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_by  BIGINT,
    deleted_at  TIMESTAMPTZ,
    UNIQUE(tenant_id, code)
);

CREATE TABLE mxid_user_group_member (
    id          BIGINT PRIMARY KEY,
    group_id    BIGINT NOT NULL REFERENCES mxid_user_group(id),
    user_id     BIGINT NOT NULL REFERENCES mxid_user(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(group_id, user_id)
);
```

### 4.5 Application Domain

```sql
CREATE TABLE mxid_app (
    id           BIGINT PRIMARY KEY,
    tenant_id    BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    name         VARCHAR(128) NOT NULL,
    code         VARCHAR(64)  NOT NULL,
    protocol     VARCHAR(16)  NOT NULL,             -- oidc/saml/cas/jwt/form
    status       SMALLINT     NOT NULL DEFAULT 1,
    icon         VARCHAR(512),
    description  TEXT,
    client_id    VARCHAR(128),
    client_secret VARCHAR(256),
    protocol_config JSONB     NOT NULL DEFAULT '{}',
    login_url    VARCHAR(512),
    redirect_uris JSONB       DEFAULT '[]',
    logout_url   VARCHAR(512),
    access_policy SMALLINT    NOT NULL DEFAULT 1,   -- 1=all 2=authorized
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_by   BIGINT,
    updated_by   BIGINT,
    deleted_at   TIMESTAMPTZ,
    UNIQUE(tenant_id, code),
    UNIQUE(client_id)
);

CREATE TABLE mxid_app_group (
    id          BIGINT PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    name        VARCHAR(128) NOT NULL,
    code        VARCHAR(64)  NOT NULL,
    sort_order  INT          NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ,
    UNIQUE(tenant_id, code)
);

CREATE TABLE mxid_app_group_rel (
    id          BIGINT PRIMARY KEY,
    app_id      BIGINT NOT NULL REFERENCES mxid_app(id),
    group_id    BIGINT NOT NULL REFERENCES mxid_app_group(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(app_id, group_id)
);

CREATE TABLE mxid_app_access (
    id            BIGINT PRIMARY KEY,
    app_id        BIGINT       NOT NULL REFERENCES mxid_app(id),
    subject_type  VARCHAR(16)  NOT NULL,            -- user/group/org/role
    subject_id    BIGINT       NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_by    BIGINT,
    UNIQUE(app_id, subject_type, subject_id)
);

CREATE TABLE mxid_app_account (
    id          BIGINT PRIMARY KEY,
    app_id      BIGINT       NOT NULL REFERENCES mxid_app(id),
    user_id     BIGINT       NOT NULL REFERENCES mxid_user(id),
    account     VARCHAR(256) NOT NULL,
    credential  VARCHAR(512),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE(app_id, user_id)
);

CREATE TABLE mxid_app_cert (
    id             BIGINT PRIMARY KEY,
    app_id         BIGINT       NOT NULL REFERENCES mxid_app(id),
    cert_type      VARCHAR(16)  NOT NULL,
    algorithm      VARCHAR(16)  NOT NULL,
    public_key     TEXT         NOT NULL,
    private_key    TEXT         NOT NULL,
    expires_at     TIMESTAMPTZ,
    status         SMALLINT     NOT NULL DEFAULT 1,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
```

### 4.6 Authentication Domain

```sql
CREATE TABLE mxid_identity_provider (
    id          BIGINT PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    name        VARCHAR(128) NOT NULL,
    code        VARCHAR(64)  NOT NULL,
    type        VARCHAR(32)  NOT NULL,
    category    VARCHAR(16)  NOT NULL,              -- social/enterprise
    config      JSONB        NOT NULL,
    status      SMALLINT     NOT NULL DEFAULT 1,
    sort_order  INT          NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ,
    UNIQUE(tenant_id, code)
);

CREATE TABLE mxid_user_mfa (
    id          BIGINT PRIMARY KEY,
    user_id     BIGINT       NOT NULL REFERENCES mxid_user(id),
    type        VARCHAR(16)  NOT NULL,
    secret      VARCHAR(256),
    config      JSONB        DEFAULT '{}',
    is_default  BOOLEAN      NOT NULL DEFAULT FALSE,
    verified    BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, type)
);
```

### 4.7 Permission Domain

```sql
CREATE TABLE mxid_role (
    id          BIGINT PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    name        VARCHAR(128) NOT NULL,
    code        VARCHAR(64)  NOT NULL,
    type        SMALLINT     NOT NULL DEFAULT 1,    -- 1=system 2=custom
    description TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ,
    UNIQUE(tenant_id, code)
);

CREATE TABLE mxid_role_binding (
    id            BIGINT PRIMARY KEY,
    role_id       BIGINT       NOT NULL REFERENCES mxid_role(id),
    subject_type  VARCHAR(16)  NOT NULL,
    subject_id    BIGINT       NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE(role_id, subject_type, subject_id)
);

CREATE TABLE mxid_permission (
    id          BIGINT PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    name        VARCHAR(128) NOT NULL,
    code        VARCHAR(128) NOT NULL,
    resource    VARCHAR(128) NOT NULL,
    action      VARCHAR(32)  NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, code)
);

CREATE TABLE mxid_role_permission (
    id            BIGINT PRIMARY KEY,
    role_id       BIGINT NOT NULL REFERENCES mxid_role(id),
    permission_id BIGINT NOT NULL REFERENCES mxid_permission(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(role_id, permission_id)
);

CREATE TABLE casbin_rule (
    id    BIGINT PRIMARY KEY,
    ptype VARCHAR(16),
    v0    VARCHAR(256),
    v1    VARCHAR(256),
    v2    VARCHAR(256),
    v3    VARCHAR(256),
    v4    VARCHAR(256),
    v5    VARCHAR(256)
);
```

### 4.8 Audit Domain

```sql
CREATE TABLE mxid_audit_log (
    id              BIGINT PRIMARY KEY,
    tenant_id       BIGINT       NOT NULL,
    actor_id        BIGINT,
    actor_name      VARCHAR(128),
    actor_type      VARCHAR(16)  NOT NULL,
    event_type      VARCHAR(64)  NOT NULL,
    event_status    SMALLINT     NOT NULL,
    resource_type   VARCHAR(32),
    resource_id     BIGINT,
    resource_name   VARCHAR(256),
    detail          JSONB        DEFAULT '{}',
    ip              VARCHAR(64),
    user_agent      VARCHAR(512),
    geo_city        VARCHAR(64),
    geo_country     VARCHAR(64),
    session_id      VARCHAR(128),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
) PARTITION BY RANGE (created_at);

CREATE INDEX idx_audit_tenant_time ON mxid_audit_log(tenant_id, created_at DESC);
CREATE INDEX idx_audit_actor ON mxid_audit_log(actor_id);
CREATE INDEX idx_audit_event ON mxid_audit_log(event_type);
```

### 4.9 System

```sql
CREATE TABLE mxid_setting (
    id          BIGINT PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    category    VARCHAR(64)  NOT NULL,
    key         VARCHAR(128) NOT NULL,
    value       JSONB        NOT NULL,
    description VARCHAR(256),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, category, key)
);

CREATE TABLE mxid_notify_record (
    id          BIGINT PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL,
    type        VARCHAR(16)  NOT NULL,
    recipient   VARCHAR(256) NOT NULL,
    subject     VARCHAR(256),
    content     TEXT,
    status      SMALLINT     NOT NULL,
    error_msg   TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
```

### 4.10 Connector (Identity Source)

```sql
CREATE TABLE mxid_connector (
    id          BIGINT PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL REFERENCES mxid_tenant(id),
    name        VARCHAR(128) NOT NULL,
    code        VARCHAR(64)  NOT NULL,
    type        VARCHAR(32)  NOT NULL,
    config      JSONB        NOT NULL,
    sync_cron   VARCHAR(64),
    status      SMALLINT     NOT NULL DEFAULT 1,
    last_sync_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ,
    UNIQUE(tenant_id, code)
);

CREATE TABLE mxid_connector_sync_log (
    id            BIGINT PRIMARY KEY,
    connector_id  BIGINT       NOT NULL REFERENCES mxid_connector(id),
    trigger_type  VARCHAR(16)  NOT NULL,
    status        SMALLINT     NOT NULL,
    users_created INT          DEFAULT 0,
    users_updated INT          DEFAULT 0,
    users_deleted INT          DEFAULT 0,
    orgs_created  INT          DEFAULT 0,
    orgs_updated  INT          DEFAULT 0,
    orgs_deleted  INT          DEFAULT 0,
    error_msg     TEXT,
    started_at    TIMESTAMPTZ  NOT NULL,
    finished_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
```

### 4.11 ER Overview

```
mxid_tenant (1) ──┬── (*) mxid_user ──┬── (1) mxid_user_detail
                   │                    ├── (*) mxid_user_identity
                   │                    ├── (*) mxid_user_password_history
                   │                    ├── (*) mxid_user_mfa
                   │                    └── (*) mxid_user_org ──── mxid_organization
                   │
                   ├── (*) mxid_organization (ltree self-ref)
                   │
                   ├── (*) mxid_user_group ──── (*) mxid_user_group_member
                   │
                   ├── (*) mxid_app ──┬── (*) mxid_app_access
                   │                  ├── (*) mxid_app_account
                   │                  ├── (*) mxid_app_cert
                   │                  └── (*) mxid_app_group_rel ── mxid_app_group
                   │
                   ├── (*) mxid_identity_provider
                   │
                   ├── (*) mxid_role ──┬── (*) mxid_role_binding
                   │                   └── (*) mxid_role_permission ── mxid_permission
                   │
                   ├── (*) mxid_connector ──── (*) mxid_connector_sync_log
                   │
                   ├── (*) mxid_setting
                   │
                   └── (*) mxid_audit_log (partitioned)

                   casbin_rule (standalone, Casbin adapter managed)
                   mxid_notify_record
```

---

## 5. Authentication Engine

### 5.1 Provider Interface

```go
type Provider interface {
    Type() string
    Authenticate(ctx context.Context, req *AuthRequest) (*AuthResult, error)
    Supported(ctx context.Context, tenantID int64) bool
}

type AuthRequest struct {
    TenantID    int64
    AuthType    string
    Credentials map[string]string
    ClientIP    string
    UserAgent   string
    SessionID   string
}

type AuthResult struct {
    UserID      int64
    Username    string
    Status      AuthStatus
    MFARequired bool
    MFATypes    []string
    SessionID   string
    Metadata    map[string]any
}
```

### 5.2 Authentication Flow

```
Submit login
    │
    ▼
Identify auth method (local/sms/social/ldap)
    │
    ▼
Call Provider.Authenticate()
    │
    ├── Fail → Record failure count → Lock if threshold → Return error
    │
    ├── Success but password expired → Return pwd_expired, force change
    │
    └── Success → Check MFA policy
                │
                ├── MFA required → Return mfa_required + available types
                │                   User submits MFA → Verify → Pass
                │
                └── No MFA → Create Session
                                │
                                ▼
                         Audit log (event bus)
                                │
                                ▼
                         Return Session Token
```

### 5.3 Session Management

Three namespaces, fully isolated:

| Namespace | Redis Prefix | Cookie Name | Cookie Path |
|-----------|-------------|-------------|-------------|
| Console (admin) | `mxid:session:console` | `mxid_console_sid` | `/api/console` |
| Portal (user) | `mxid:session:portal` | `mxid_portal_sid` | `/api/portal` |
| Protocol (SSO) | `mxid:session:protocol` | `mxid_proto_sid` | `/protocol` |

All cookies: `HttpOnly`, `Secure` (prod), `SameSite` per context.

### 5.4 Social Login Flow

```
User clicks "GitHub Login"
    │
    ▼
Portal redirects → /auth/social/github?tenant_id=xxx
    │
    ▼
Backend builds OAuth2 authorize URL → 302 to GitHub
    │
    ▼
GitHub authorizes → callback /auth/social/github/callback?code=xxx
    │
    ▼
Backend exchanges code for token → fetch user info
    │
    ▼
Lookup mxid_user_identity (provider_type=github, external_id=xxx)
    │
    ├── Bound → Get user_id → Create Session → Redirect portal
    │
    └── Not bound → Configurable:
                      ├── Auto-register: create user + identity → Session
                      └── Require bind: redirect to bind page
```

---

## 6. SSO Protocol Engine

### 6.1 Resolver Layer

Protocol layer accesses business services ONLY through resolver interfaces:

```go
type AppResolver interface {
    GetApp(ctx context.Context, identifier string) (*AppConfig, error)
    GetCert(ctx context.Context, appID int64, certType string) (*CertConfig, error)
}

type IdentityResolver interface {
    ResolveUser(ctx context.Context, userID int64) (*IdentityInfo, error)
    ResolveClaims(ctx context.Context, userID int64, mapping []ClaimMapping) (map[string]any, error)
}

type SessionResolver interface {
    GetSSOSession(ctx context.Context, sessionID string) (*SSOSession, error)
    CreateSSOSession(ctx context.Context, userID int64, authType string) (*SSOSession, error)
}
```

### 6.2 OIDC (OpenID Connect 1.0)

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/protocol/oidc/.well-known/openid-configuration` | Discovery |
| GET | `/protocol/oidc/authorize` | Authorization |
| POST | `/protocol/oidc/token` | Token |
| GET | `/protocol/oidc/userinfo` | UserInfo |
| GET | `/protocol/oidc/jwks` | JWKS |
| POST | `/protocol/oidc/revoke` | Token revocation |
| POST | `/protocol/oidc/introspect` | Token introspection |
| GET | `/protocol/oidc/end-session` | Logout |

**Grant types:** authorization_code (+PKCE), refresh_token, client_credentials

**Scopes:** openid, profile, email, phone, groups

### 6.3 SAML 2.0

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/protocol/saml/:app_code/metadata` | SP/IDP metadata |
| POST | `/protocol/saml/:app_code/sso` | SSO (POST binding) |
| GET | `/protocol/saml/:app_code/sso` | SSO (Redirect binding) |
| POST | `/protocol/saml/:app_code/slo` | Single logout |

**Features:** IDP-Initiated SSO, SP-Initiated SSO, signed assertions (RSA-SHA256), encrypted assertions (optional), NameID formats, attribute mapping.

**Library:** crewjam/saml

### 6.4 CAS 3.0

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/protocol/cas/:app_code/login` | Login entry |
| GET | `/protocol/cas/:app_code/validate` | CAS 1.0 validate |
| GET | `/protocol/cas/:app_code/serviceValidate` | CAS 2.0 validate (XML) |
| GET | `/protocol/cas/:app_code/p3/serviceValidate` | CAS 3.0 validate (with attributes) |
| GET | `/protocol/cas/:app_code/logout` | Logout |

**Implementation:** Custom (CAS protocol is simple). ST stored in Redis, TTL 30s, single-use.

### 6.5 JWT SSO (P1)

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/protocol/jwt/:app_code/login` | Generate JWT redirect |
| POST | `/protocol/jwt/:app_code/verify` | Verify JWT (target app calls) |

### 6.6 FORM Fill (P1)

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/protocol/form/:app_code/login` | Return auto-submit form page |

---

## 7. Frontend Architecture

### 7.1 Tech Stack

- React 18 + TypeScript
- Vite (build tool)
- TailwindCSS (utility-first CSS)
- Shadcn/ui (headless components, fully customizable)
- Framer Motion (animations)
- Zustand (state management)
- React Router (routing)
- Axios (HTTP client)
- pnpm workspaces (monorepo)

### 7.2 Design System

**Color palette (3 colors):**

| Role | Color | Usage |
|------|-------|-------|
| Primary | Blue `#3b82f6` | Brand, actions, links, active states |
| Neutral | Slate `#0f172a` → `#f8fafc` | Backgrounds, text, borders, layering |
| Accent | Emerald `#10b981` | Success, online status |

**Semantic colors:** Success `#10b981`, Warning `#f59e0b`, Error `#ef4444`, Info `#3b82f6`

**Animation strategy:**
- Static-first: no decorative animations, no carousels, no floating elements
- Transition animations: page switch (fade+slide 250ms), modal (scale 0.95+fade), sidebar expand/collapse, list add/remove (AnimatePresence)
- High interactivity: row hover, selection states, batch action bars, real-time validation, debounce search, drag-to-sort, context menus

### 7.3 Console Pages

- Dashboard (overview, login trends)
- User management (CRUD, status, password reset, sessions)
- Organization management (tree view, members)
- User group management
- Application management (CRUD, protocol config, access policy, certs)
- Application group management
- Identity provider configuration
- Connector (identity source) management
- Permission management (roles, permissions, bindings)
- Audit log viewer
- System settings (security, password, login, notification)
- Session management

### 7.4 Portal Pages

- Login (multi-method)
- MFA verification
- Forgot password
- My apps (grid view, launch)
- Profile
- Security settings (change password, MFA, identity bindings, sessions)
- OAuth consent screen

---

## 8. API Design

### 8.1 Response Format

```json
// Success
{ "code": 0, "message": "ok", "data": { ... } }

// Paginated
{ "code": 0, "message": "ok", "data": { "items": [...], "total": 150, "page": 1, "page_size": 20 } }

// Error
{ "code": 40101, "message": "token expired", "detail": "session not found or expired" }
```

### 8.2 Error Codes

```
5-digit: first 3 = HTTP status, last 2 = business code

400xx — Request errors
  40001: Validation failed
  40002: Duplicate resource

401xx — Authentication errors
  40101: Token expired
  40102: Token invalid
  40103: MFA required
  40104: Account locked
  40105: Password expired

403xx — Permission errors
  40301: No permission
  40302: Insufficient role

404xx — Not found
  40401: User not found
  40402: App not found
  40403: Org not found

500xx — Server errors
  50001: Internal error
  50002: Database error
  50003: Redis connection failed
```

### 8.3 Console API

```
Auth:
  POST   /api/console/auth/login
  POST   /api/console/auth/logout
  GET    /api/console/auth/me

Users:
  GET    /api/console/users
  POST   /api/console/users
  GET    /api/console/users/:id
  PUT    /api/console/users/:id
  DELETE /api/console/users/:id
  PUT    /api/console/users/:id/status
  PUT    /api/console/users/:id/password
  GET    /api/console/users/:id/identities
  GET    /api/console/users/:id/sessions
  DELETE /api/console/users/:id/sessions/:sid

Organizations:
  GET    /api/console/orgs
  POST   /api/console/orgs
  GET    /api/console/orgs/:id
  PUT    /api/console/orgs/:id
  DELETE /api/console/orgs/:id
  PUT    /api/console/orgs/:id/move
  GET    /api/console/orgs/:id/members
  POST   /api/console/orgs/:id/members
  DELETE /api/console/orgs/:id/members/:uid

User Groups:
  GET    /api/console/groups
  POST   /api/console/groups
  GET    /api/console/groups/:id
  PUT    /api/console/groups/:id
  DELETE /api/console/groups/:id
  GET    /api/console/groups/:id/members
  POST   /api/console/groups/:id/members
  DELETE /api/console/groups/:id/members/:uid

Applications:
  GET    /api/console/apps
  POST   /api/console/apps
  GET    /api/console/apps/:id
  PUT    /api/console/apps/:id
  DELETE /api/console/apps/:id
  PUT    /api/console/apps/:id/status
  GET    /api/console/apps/:id/config
  PUT    /api/console/apps/:id/config
  GET    /api/console/apps/:id/access
  POST   /api/console/apps/:id/access
  DELETE /api/console/apps/:id/access/:aid
  GET    /api/console/apps/:id/certs
  POST   /api/console/apps/:id/certs
  DELETE /api/console/apps/:id/certs/:cid

App Groups:
  GET    /api/console/app-groups
  POST   /api/console/app-groups
  PUT    /api/console/app-groups/:id
  DELETE /api/console/app-groups/:id
  POST   /api/console/app-groups/:id/apps
  DELETE /api/console/app-groups/:id/apps/:aid

Identity Providers:
  GET    /api/console/identity-providers
  POST   /api/console/identity-providers
  GET    /api/console/identity-providers/:id
  PUT    /api/console/identity-providers/:id
  DELETE /api/console/identity-providers/:id
  PUT    /api/console/identity-providers/:id/status

Connectors:
  GET    /api/console/connectors
  POST   /api/console/connectors
  GET    /api/console/connectors/:id
  PUT    /api/console/connectors/:id
  DELETE /api/console/connectors/:id
  POST   /api/console/connectors/:id/sync
  GET    /api/console/connectors/:id/logs

Permissions:
  GET    /api/console/roles
  POST   /api/console/roles
  GET    /api/console/roles/:id
  PUT    /api/console/roles/:id
  DELETE /api/console/roles/:id
  GET    /api/console/roles/:id/permissions
  PUT    /api/console/roles/:id/permissions
  GET    /api/console/roles/:id/members
  POST   /api/console/roles/:id/members
  DELETE /api/console/roles/:id/members/:mid
  GET    /api/console/permissions

Audit:
  GET    /api/console/audit/logs
  GET    /api/console/audit/stats

Settings:
  GET    /api/console/settings/:category
  PUT    /api/console/settings/:category

Sessions:
  GET    /api/console/sessions
  DELETE /api/console/sessions/:sid

Dashboard:
  GET    /api/console/dashboard/overview
  GET    /api/console/dashboard/login-trend
```

### 8.4 Portal API

```
Auth:
  POST   /api/portal/auth/login
  POST   /api/portal/auth/logout
  POST   /api/portal/auth/mfa/verify
  POST   /api/portal/auth/forgot-password
  POST   /api/portal/auth/reset-password
  GET    /api/portal/auth/me

Social Login:
  GET    /api/portal/auth/social/:provider
  GET    /api/portal/auth/social/:provider/callback

Apps:
  GET    /api/portal/apps
  GET    /api/portal/apps/:id/launch

Profile:
  GET    /api/portal/profile
  PUT    /api/portal/profile
  PUT    /api/portal/profile/avatar

Security:
  PUT    /api/portal/security/password
  GET    /api/portal/security/mfa
  POST   /api/portal/security/mfa/totp/setup
  POST   /api/portal/security/mfa/totp/verify
  DELETE /api/portal/security/mfa/totp
  GET    /api/portal/security/identities
  POST   /api/portal/security/identities/:provider/bind
  DELETE /api/portal/security/identities/:provider/unbind
  GET    /api/portal/security/sessions
  DELETE /api/portal/security/sessions/:sid
```

### 8.5 OpenAPI (Third-party)

```
Auth: API Key (X-API-Key header) or OAuth2 Client Credentials

Users:
  GET    /api/v1/users
  POST   /api/v1/users
  GET    /api/v1/users/:id
  PUT    /api/v1/users/:id
  DELETE /api/v1/users/:id

Organizations:
  GET    /api/v1/organizations
  POST   /api/v1/organizations
  GET    /api/v1/organizations/:id
  PUT    /api/v1/organizations/:id
  DELETE /api/v1/organizations/:id

App Accounts:
  GET    /api/v1/app-accounts
  POST   /api/v1/app-accounts
  PUT    /api/v1/app-accounts/:id
  DELETE /api/v1/app-accounts/:id
```

---

## 9. Security

| Domain | Measure |
|--------|---------|
| Password storage | Argon2id (preferred) or bcrypt |
| Password policy | Configurable: min length, complexity, history N, expiry days |
| Account lockout | N failures → lock M minutes, configurable |
| Session | Redis-backed, HttpOnly+Secure+SameSite cookies, idle + absolute timeout |
| CSRF | SameSite cookie + double submit token (except OIDC endpoints) |
| XSS | CSP header, React default escaping, input validation |
| SQL injection | GORM parameterized queries, no raw SQL concatenation |
| Sensitive data | client_secret/private_key AES-256-GCM encrypted, log masking |
| Transport | HTTPS enforced in prod, HSTS header |
| Rate limiting | Redis sliding window: login 5/min, API 100/min |
| Audit | All critical operations logged, immutable (write-only) |
| JWT signing | RS256 asymmetric, key rotation support |
| CORS | Whitelist mode, no wildcard `*` |

---

## 10. Deployment

### 10.1 Dev Environment

```
Go Backend      :10050  ← air hot-reload
Console SPA     :3500   ← Vite dev server (proxy → :10050)
Portal SPA      :3501   ← Vite dev server (proxy → :10050)
PostgreSQL      ← Host machine (existing docker-compose, host.docker.internal)
Redis           ← Host machine (existing docker-compose, host.docker.internal)
```

Toolchain: `air` + `docker-compose` + `Makefile`

MXID service runs in Docker. Databases accessed via `host.docker.internal`.

### 10.2 Production Environment

```
Nginx/Gateway (:80/:443)
  /              → Console SPA (static files)
  /portal        → Portal SPA  (static files)
  /api/*         → MXID :8080  (reverse proxy)
  /auth/*        → MXID :8080
  /protocol/*    → MXID :8080
        │
        ▼
MXID Server (:8080)  ← Single binary, horizontally scalable (stateless)
        │
   PG 16 + Redis 7
```

### 10.3 Deploy Directory Structure

```
deploy/
├── dockerfile/
│   └── Dockerfile
├── compose/
│   └── docker-compose.yml       # MXID service only (no PG/Redis)
├── nginx/
│   └── nginx.conf
└── scripts/
    └── init-db.sh
```

### 10.4 Single Binary Build

Frontend assets embedded via Go `embed`:

```go
//go:embed all:web/apps/console/dist
var consoleFS embed.FS

//go:embed all:web/apps/portal/dist
var portalFS embed.FS
```

### 10.5 Configuration

```yaml
server:
  port: 8080
  mode: debug

database:
  host: host.docker.internal
  port: 5432
  name: mxid
  user: mxid
  password: ""
  max_open_conns: 50
  max_idle_conns: 10

redis:
  host: host.docker.internal
  port: 6379
  db: 0
  password: ""

session:
  idle_timeout: 30m
  absolute_timeout: 12h
  cookie_secure: false

security:
  password:
    min_length: 8
    require_uppercase: true
    require_lowercase: true
    require_number: true
    require_special: false
    history_count: 5
    expire_days: 90
    expire_warn_days: 7
  login:
    max_failed_attempts: 5
    lockout_duration: 15m
    captcha_after_failures: 3
  rate_limit:
    login: "5/m"
    api: "100/m"

jwt:
  signing_algorithm: RS256
  access_token_ttl: 15m
  refresh_token_ttl: 7d

tenant:
  default_id: 1

log:
  level: info
  format: json
  output: stdout
```

---

## 11. MVP Scope

### 11.1 What's In

| Module | MVP Scope |
|--------|-----------|
| User | CRUD, password policy, status, profile |
| Organization | Tree CRUD, member management, ltree |
| User Group | CRUD, member management |
| Application | CRUD, protocol config, access policy, app groups |
| Authentication | Username/password, SMS, email |
| MFA | TOTP |
| Protocol | OIDC (+PKCE), SAML 2.0, CAS 3.0 |
| Permission | RBAC roles/permissions, Casbin |
| Audit | Full audit logging, query, statistics |
| Settings | Password policy, login policy, notification config |
| Session | Redis management, kick, list |
| Console | Full admin UI |
| Portal | Login, app list, profile, security settings |
| Deploy | Docker Compose + single binary |

### 11.2 What's Not (deferred)

| Phase | Features |
|-------|----------|
| P1 | Social login, LDAP/AD, JWT SSO, FORM fill, identity providers, audit export, SMS MFA, self-service password reset, storage config |
| P2 | Approval workflow, SCIM 2.0, WebAuthn/FIDO2, ABAC, DingTalk/Feishu/WeCom sync, webhooks, full multi-tenant, i18n, K8s Helm |
| P3 | Adaptive MFA, device management, API gateway integration, custom login themes, analytics |

---

## 12. Roadmap

```
P0 — MVP (Core Loop)
  User / Org / Group / App management
  Auth: password + SMS + email + TOTP MFA
  Protocol: OIDC + SAML + CAS
  Permission: RBAC
  Audit logging
  Console + Portal UI
  Docker deployment

P1 — Enterprise Enhancement
  Social login (GitHub/DingTalk/Feishu/WeChat)
  LDAP/AD identity source + sync
  JWT SSO + FORM fill protocol
  Identity provider management
  Audit log export
  SMS MFA
  Self-service password reset
  Storage config (avatar/cert files)

P2 — Commercial Differentiation
  Approval workflow engine
  SCIM 2.0 sync
  WebAuthn/FIDO2
  ABAC policy engine
  DingTalk/Feishu/WeCom identity source sync
  Webhook/event notifications
  Full multi-tenant implementation
  Internationalization (i18n)
  K8s Helm Chart

P3 — Advanced Features
  Adaptive MFA / risk engine
  Device management
  API gateway integration
  SSO session global management
  Custom login page themes
  Data analytics & reporting
```
