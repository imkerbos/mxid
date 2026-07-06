package app

// EE license cross-pod reload. license.SetCurrent(mgr) sets a process-global
// atomic.Pointer (pkg/ee/license), so activating/renewing/downgrading a
// license through the console (settings.Handler.putLicense) only updates the
// pod that served the request — every OTHER replica keeps enforcing the OLD
// edition (CE caps / EE feature gates) until it restarts. This file gives
// every replica a way to converge: reloadLicense is the single re-read+install
// step, used at boot and by startLicenseReloadSubscriber, which reacts to a
// Redis broadcast published by putLicense.

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/imkerbos/mxid/internal/domain/platformconfig"
	"github.com/imkerbos/mxid/internal/domain/setting"
	"github.com/imkerbos/mxid/pkg/ee/license"
)

// licenseReloadChannel is the Redis pub/sub channel used to fan a license
// change out to every replica. Payload is unused (a reload always re-reads
// the full row from platform config), so any message is a trigger.
const licenseReloadChannel = "license:reload"

// reloadLicense re-reads the persisted license from platform config and
// installs it as the process-global active license (license.SetCurrent).
// Used at boot AND by startLicenseReloadSubscriber so every replica
// converges on the same edition. No token → CE; an invalid/expired token
// downgrades to CE limits with existing data grandfathered (see
// license.Load); callers that need to log the outcome use the returned
// Manager (mgr.LoadErr(), mgr.Edition(), ...).
func reloadLicense(ctx context.Context, platform *platformconfig.Service) *license.Manager {
	token := ""
	var lic setting.License
	if err := platform.Get(ctx, platformconfig.KeyLicense, &lic); err == nil {
		token = lic.Key
	}
	mgr := license.Load(token, time.Now())
	license.SetCurrent(mgr)
	return mgr
}

// startLicenseReloadSubscriber reloads this pod's active license whenever a
// peer replica's console handler (or this pod's own, redundantly) broadcasts
// a change over licenseReloadChannel. Mirrors startCasbinResyncSubscriber
// (app/adapters_authz.go): explicit params rather than *bootstrap.App so it
// is unit-testable against miniredis, ctx-cancellable goroutine, nil-safe
// when Redis isn't configured (this pod then stays boot-time-license-only,
// same as before cross-pod reload existed).
func startLicenseReloadSubscriber(ctx context.Context, rdb *redis.Client, platform *platformconfig.Service, logger *zap.Logger) {
	if rdb == nil {
		return
	}
	sub := rdb.Subscribe(ctx, licenseReloadChannel)
	ch := sub.Channel()
	go func() {
		defer sub.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-ch:
				if !ok {
					return
				}
				mgr := reloadLicense(context.Background(), platform)
				if logger != nil {
					logger.Info("license reloaded (peer broadcast)",
						zap.String("edition", string(mgr.Edition())))
				}
			}
		}
	}()
}
