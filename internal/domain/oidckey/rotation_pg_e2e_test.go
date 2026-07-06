package oidckey

// Postgres end-to-end integration test. Skipped unless MXID_E2E_DSN points at
// a THROWAWAY database. Proves the enforcement the sqlite unit tests cannot:
// the partial unique index from migration 000053 keeps exactly one ACTIVE row
// even when two rotators race Rotate concurrently with no leader lock (the
// scenario the leader lock in app/adapters_oidcop.go exists to prevent in
// production; this test exercises the last-resort DB guard directly).

import (
	"context"
	"encoding/base64"
	"os"
	"sync"
	"testing"

	"github.com/imkerbos/mxid/pkg/crypto"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const e2eOIDCKeysetTable = `
DROP TABLE IF EXISTS mxid_oidc_keyset;
CREATE TABLE mxid_oidc_keyset (
    id          BIGINT PRIMARY KEY,
    kid         VARCHAR(64)  NOT NULL UNIQUE,
    algorithm   VARCHAR(16)  NOT NULL DEFAULT 'RS256',
    public_key  TEXT         NOT NULL,
    private_key TEXT         NOT NULL,
    status      SMALLINT     NOT NULL DEFAULT 1,
    not_before  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX idx_oidc_keyset_status ON mxid_oidc_keyset (status);
CREATE UNIQUE INDEX IF NOT EXISTS uq_oidc_keyset_one_active
    ON mxid_oidc_keyset (status)
    WHERE status = 1;
`

func TestZZ_E2E_Postgres_RotateSingleActive(t *testing.T) {
	dsn := os.Getenv("MXID_E2E_DSN")
	if dsn == "" {
		t.Skip("MXID_E2E_DSN not set")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open pg: %v", err)
	}
	if err := db.Exec(e2eOIDCKeysetTable).Error; err != nil {
		t.Fatalf("create keyset table + index: %v", err)
	}

	mk, err := crypto.NewMasterKey(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatalf("master key: %v", err)
	}
	idGen, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("id gen: %v", err)
	}
	svc := NewService(db, idGen, mk)

	ctx := context.Background()
	if _, err := svc.EnsureActive(ctx); err != nil {
		t.Fatalf("seed active key: %v", err)
	}

	const rotators = 2
	var wg sync.WaitGroup
	errs := make([]error, rotators)
	for i := range rotators {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Each rotator gets its own Service/connection, simulating two
			// separate replicas racing Rotate with no leader lock.
			rdb, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
			if err != nil {
				errs[i] = err
				return
			}
			rsvc := NewService(rdb, idGen, mk)
			_, errs[i] = rsvc.Rotate(ctx)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("rotator %d returned a hard error (unique violation should have been swallowed): %v", i, err)
		}
	}

	var activeCount int64
	if err := db.Table("mxid_oidc_keyset").Where("status = ?", StatusActive).Count(&activeCount).Error; err != nil {
		t.Fatalf("count active: %v", err)
	}
	if activeCount != 1 {
		t.Fatalf("concurrent Rotate left %d active keys, want exactly 1", activeCount)
	}
	t.Logf("E2E PASS: concurrent Rotate under partial unique index left exactly 1 active key")
}
