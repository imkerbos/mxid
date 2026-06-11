package portal

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/domain/consent"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/mailer"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// Module holds the wired portal gateway components.
type Module struct{}

// Register wires up the portal gateway handlers and registers routes.
//
// rdb + logger + portalURL are required for the email-verification flow
// (token storage in Redis, dev link logging, click-back redirect).
func Register(
	rg *gin.RouterGroup,
	userQ UserQuerier,
	appQ AppQuerier,
	sessQ SessionQuerier,
	mfaQ MFAQuerier,
	idQ IdentityQuerier,
	consentSvc *consent.Service,
	consentQ ConsentQuerier,
	tenantID int64,
	rdb *redis.Client,
	logger *zap.Logger,
	portalURL string,
	mailerSvc *mailer.Mailer,
	bus *event.Bus,
) *Module {
	// One-time wiring of the SSE broker to the in-process event bus.
	// Subsequent Register calls (e.g. in tests) would double-subscribe,
	// but Register is only called once per server lifetime.
	AttachBusSubscribers(bus)
	// Apps
	registerAppsRoutes(rg, &appsHandler{
		appQuerier: appQ,
		bus:        bus,
	})

	// Profile
	registerProfileRoutes(rg, NewProfileHandler(userQ))

	// Real-time event stream (SSE) — used by portal SPA to refetch /apps,
	// /tenants etc when policy changes.
	registerEventsRoutes(rg, &eventsHandler{bus: bus})

	// Email verification
	registerEmailVerifyRoutes(rg, NewEmailVerifyHandler(rdb, userQ, logger, portalURL, mailerSvc, tenantID))

	// Security routes are now mounted from cmd/server/main.go for BOTH
	// portal and console groups so the engine's shared MFA rate limiter
	// can be threaded into NewSecurityHandler. Keeping the wiring in one
	// place also keeps the two route groups in lock-step.

	// Consent
	registerConsentRoutes(rg, &consentHandler{
		consentSvc: consentSvc,
		queryier:   consentQ,
		tenantID:   tenantID,
	})

	return &Module{}
}

// parseID parses a string path parameter to int64.
func parseID(s string) (int64, error) {
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid id: %s", s)
	}
	return id, nil
}
