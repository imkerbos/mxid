package app

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/internal/domain/conditionalaccess"
	"github.com/imkerbos/mxid/internal/domain/setting"
	"github.com/imkerbos/mxid/pkg/ee/registry"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/geoip"
)

// loginHistoryAdapter reads recent successful logins from mxid_login_record so
// the conditional-access signal computer can derive new-country / impossible-
// travel signals.
type loginHistoryAdapter struct{ db *gorm.DB }

func (l loginHistoryAdapter) RecentSuccessful(ctx context.Context, userID int64, limit int) ([]conditionalaccess.LoginEvent, error) {
	var rows []struct {
		IP        *string   `gorm:"column:ip"`
		CreatedAt time.Time `gorm:"column:created_at"`
	}
	err := l.db.WithContext(ctx).
		Table("mxid_login_record").
		Select("ip, created_at").
		Where("user_id = ? AND success = ?", userID, true).
		Order("created_at DESC").
		Limit(limit).
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	events := make([]conditionalaccess.LoginEvent, 0, len(rows))
	for _, r := range rows {
		ip := ""
		if r.IP != nil {
			ip = *r.IP
		}
		events = append(events, conditionalaccess.LoginEvent{IP: ip, At: r.CreatedAt})
	}
	return events, nil
}

// caRiskLogger records the A3 fallback — a risky login allowed through because
// the user has no second factor to challenge. Publishes a login.risk event the
// audit pipeline persists (so it's queryable in the console), and logs at WARN
// for live operability.
type caRiskLogger struct {
	logger *zap.Logger
	bus    *event.Bus
}

func (l caRiskLogger) Risk(ctx context.Context, userID, tenantID int64, ip string, reasons []string) {
	l.logger.Warn("conditional-access risk: login allowed without a second factor",
		zap.Int64("user_id", userID),
		zap.Int64("tenant_id", tenantID),
		zap.String("ip", ip),
		zap.Strings("reasons", reasons))
	if l.bus != nil {
		l.bus.Publish(ctx, event.Event{
			Type: event.LoginRisk,
			Payload: map[string]any{
				"user_id":   userID,
				"tenant_id": tenantID,
				"ip":        ip,
				"reasons":   reasons,
			},
		})
	}
}

// buildConditionalAccess wires the adaptive-authentication service from app
// dependencies. The returned service is inert until the tenant's
// security.conditional_access policy is enabled.
func buildConditionalAccess(a *bootstrap.App, settings *setting.Service, geo geoip.Resolver) *conditionalaccess.Service {
	deviceSvc := conditionalaccess.NewDeviceService(conditionalaccess.NewGormDeviceRepo(a.DB), a.IDGen)
	computer := conditionalaccess.NewSignalComputer(geo, loginHistoryAdapter{db: a.DB}, deviceSvc)

	cfg := func(ctx context.Context, tenantID int64) conditionalaccess.RuntimeConfig {
		c, err := settings.ConditionalAccess(ctx, tenantID)
		if err != nil {
			c = setting.DefaultConditionalAccess()
		}
		return conditionalaccess.RuntimeConfig{
			Policy: conditionalaccess.Policy{
				Enabled:            c.Enabled,
				OnNewCountry:       c.OnNewCountry,
				OnImpossibleTravel: c.OnImpossibleTravel,
				OnNewDevice:        c.OnNewDevice,
			},
			TravelWindow: time.Duration(c.ImpossibleTravelWindowMinutes) * time.Minute,
		}
	}

	return conditionalaccess.NewService(cfg, computer, deviceSvc, caRiskLogger{logger: a.Logger, bus: a.EventBus})
}

// assessLoginRiskAdapter exposes conditional access to the EE federated-login
// path. Two gaps it closes, both of which made an external-only user invisible
// to adaptive authentication:
//
//   - the device was never remembered, so the device history stayed empty and
//     every federated sign-in would read as an unseen device;
//   - the assessment never ran, so a risky sign-in (new country, impossible
//     journey) left no record at all for a user who signs in only this way.
//
// The verdict is discarded, exactly as the local path discards it — see
// registry.AssessLoginRiskFunc for why forcing a factor here is a separate
// decision rather than an oversight.
func assessLoginRiskAdapter(ca *conditionalaccess.Service, cookieDomain string, cookieSecure bool, logger *zap.Logger) registry.AssessLoginRiskFunc {
	return func(c *gin.Context, tenantID, userID int64, secondFactorCleared bool) {
		if ca == nil || userID == 0 || c == nil {
			return
		}
		ctx := c.Request.Context()
		deviceID := authn.ReadOrMintDeviceID(c)

		if _, err := ca.Assess(ctx, conditionalaccess.AssessInput{
			UserID:          userID,
			TenantID:        tenantID,
			IP:              c.ClientIP(),
			UserAgent:       c.Request.UserAgent(),
			DeviceID:        deviceID,
			CanSecondFactor: secondFactorCleared,
		}); err != nil {
			// A signal that cannot be computed (geo lookup down, history
			// unreadable) must not cost the user their session.
			logger.Warn("conditional access: assess federated login failed",
				zap.Int64("user_id", userID), zap.Error(err))
		}

		// Remember the device even when the policy is off, so history has
		// accumulated by the time an admin turns it on — the same reason
		// RememberDevice runs unconditionally on the local path.
		if deviceID == "" {
			return
		}
		if err := ca.RememberDevice(ctx, tenantID, userID, deviceID, c.Request.UserAgent()); err != nil {
			logger.Warn("conditional access: remember device failed",
				zap.Int64("user_id", userID), zap.Error(err))
			return
		}
		authn.SetDeviceCookie(c, deviceID, cookieDomain, cookieSecure)
	}
}
