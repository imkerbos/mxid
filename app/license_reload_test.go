package app

// Verifies license reload: (1) reloadLicense re-reads the persisted token
// from platform config and installs it as the process-global active license,
// and (2) startLicenseReloadSubscriber does the same when a peer replica
// (or this pod's own settings handler) broadcasts over licenseReloadChannel
// — the cross-pod half of license hot-reload. Without this, activating a
// license via the console only updates the pod that served the request;
// every other replica keeps enforcing the stale edition until it restarts.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/imkerbos/mxid/internal/domain/platformconfig"
	"github.com/imkerbos/mxid/internal/domain/setting"
	"github.com/imkerbos/mxid/pkg/ee/license"
)

func newTestPlatformConfig(t *testing.T) (*platformconfig.Service, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&platformconfig.PlatformConfig{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return platformconfig.NewService(platformconfig.NewRepository(db)), db
}

// seedLicense inserts a platform-config row directly via a plain GORM Create
// rather than through platformconfig.Service.Set: the repository's Upsert
// uses `gorm.Expr("now()")` (Postgres-only, the only backend this table ever
// runs against in production) which sqlite's driver has no such function
// for. reloadLicense only exercises Service.Get, so a direct insert is a
// faithful seed for these tests without needing a Postgres test DB.
func seedLicense(t *testing.T, db *gorm.DB, key string) {
	t.Helper()
	raw, err := json.Marshal(setting.License{Key: key})
	if err != nil {
		t.Fatalf("marshal license: %v", err)
	}
	if err := db.Create(&platformconfig.PlatformConfig{
		Key:       platformconfig.KeyLicense,
		Value:     raw,
		UpdatedAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("seed license: %v", err)
	}
}

func TestReloadLicense_InstallsPersistedToken(t *testing.T) {
	ctx := context.Background()
	platform, db := newTestPlatformConfig(t)

	const seededKey = "garbage-unsigned-token"
	seedLicense(t, db, seededKey)

	// Start from a known-different state so the assertion below can't pass
	// by accident (e.g. reloadLicense being a no-op).
	license.SetCurrent(license.CE())

	mgr := reloadLicense(ctx, platform)
	if mgr == nil {
		t.Fatal("reloadLicense returned nil manager")
	}

	want := license.Load(seededKey, time.Now())
	if got, exp := mgr.Edition(), want.Edition(); got != exp {
		t.Errorf("edition = %q, want %q", got, exp)
	}
	if got, exp := mgr.State(), want.State(); got != exp {
		t.Errorf("state = %q, want %q", got, exp)
	}

	// license.Current() (the process-global) must reflect the reload, not
	// just the returned value.
	current := license.Current()
	if current == nil {
		t.Fatal("license.Current() is nil after reloadLicense")
	}
	if got, exp := current.Edition(), want.Edition(); got != exp {
		t.Errorf("license.Current().Edition() = %q, want %q", got, exp)
	}
}

func TestReloadLicense_NoStoredLicenseFallsBackToCE(t *testing.T) {
	ctx := context.Background()
	platform, _ := newTestPlatformConfig(t)

	mgr := reloadLicense(ctx, platform)
	if mgr.IsEE() {
		t.Errorf("expected CE when no license is stored, got IsEE=true")
	}
}

func TestStartLicenseReloadSubscriber_PeerBroadcastTriggersReload(t *testing.T) {
	rdb := newTestRedis(t)
	platform, db := newTestPlatformConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Seed a license AFTER installing CE as current, then publish — the
	// subscriber must re-read platform config on receipt, not use a stale
	// snapshot taken at subscribe time.
	license.SetCurrent(license.CE())
	const seededKey = "garbage-unsigned-token-2"
	seedLicense(t, db, seededKey)

	startLicenseReloadSubscriber(ctx, rdb, platform, nil)

	deadline := time.Now().Add(time.Second)
	for rdb.PubSubNumSub(ctx, licenseReloadChannel).Val()[licenseReloadChannel] == 0 {
		if time.Now().After(deadline) {
			t.Fatal("subscriber never attached to channel")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := rdb.Publish(ctx, licenseReloadChannel, "1").Err(); err != nil {
		t.Fatalf("publish: %v", err)
	}

	want := license.Load(seededKey, time.Now())
	deadline = time.Now().Add(time.Second)
	for {
		if current := license.Current(); current != nil && current.Edition() == want.Edition() && current.State() == want.State() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("license reload subscriber did not converge within timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestStartLicenseReloadSubscriber_NilRedisIsNoop(t *testing.T) {
	platform, _ := newTestPlatformConfig(t)

	// Must not panic when Redis is unavailable.
	startLicenseReloadSubscriber(context.Background(), nil, platform, nil)
	time.Sleep(50 * time.Millisecond)
}
