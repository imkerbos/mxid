package bootstrap

import (
	"io"
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/response"
	"go.uber.org/zap"
)

// InitRouter creates the Gin engine with base middleware and route groups.
func InitRouter(cfg *ServerConfig, logger *zap.Logger) *gin.Engine {
	if cfg.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Suppress Gin's default debug logging
	gin.DefaultWriter = io.Discard
	gin.DefaultErrorWriter = io.Discard

	r := gin.New()

	// Trusted proxies: gin's c.ClientIP() walks X-Forwarded-For only when
	// the immediate peer is in this list. Default = RFC1918 + loopback so
	// dev compose (vite container in 172.x, host gateway in 192.168.x)
	// reports the real browser IP via XFF. Production should override via
	// config to the actual edge proxy(es).
	proxies := cfg.TrustedProxies
	usingBroadDefault := false
	if len(proxies) == 0 {
		proxies = []string{
			"127.0.0.1/32", "::1/128",
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		}
		usingBroadDefault = true
	}
	if err := r.SetTrustedProxies(proxies); err != nil {
		logger.Warn("set trusted proxies failed", zap.Strings("cidrs", proxies), zap.Error(err))
	}
	// Footgun guard: the broad RFC1918 default is a dev convenience. In release
	// it MUST be narrowed to the actual edge proxy IP(s) — otherwise on-prem
	// intranet clients (10.x / 192.168.x) are treated as trusted proxies and
	// their real IP is dropped, collapsing every internal user onto one bucket
	// for rate-limit / audit / conditional-access. Warn loudly so it's caught.
	if usingBroadDefault && cfg.Mode == "release" {
		logger.Warn("trusted_proxies unset in release mode — using broad RFC1918 default; "+
			"narrow server.trusted_proxies to the edge proxy IP(s) or intranet client IPs will be mis-resolved",
			zap.Strings("default_cidrs", proxies))
	}

	// Zap-based recovery middleware
	r.Use(zapRecovery(logger))

	// Health check
	r.GET("/health", func(c *gin.Context) {
		response.OK(c, gin.H{
			"status":  "healthy",
			"service": "mxid",
		})
	})

	// Readiness check
	r.GET("/ready", func(c *gin.Context) {
		response.OK(c, gin.H{
			"status": "ready",
		})
	})

	// NoRoute handler
	r.NoRoute(func(c *gin.Context) {
		response.Error(c, http.StatusNotFound, 40400, "route not found", "")
	})

	return r
}

// RegisterRouteGroups creates the main API and protocol route groups.
func RegisterRouteGroups(r *gin.Engine) (*gin.RouterGroup, *gin.RouterGroup, *gin.RouterGroup, *gin.RouterGroup) {
	console := r.Group("/api/v1/console")
	portal := r.Group("/api/v1/portal")
	openapi := r.Group("/openapi/v1")
	protocol := r.Group("/protocol")

	return console, portal, openapi, protocol
}

// zapRecovery returns a Gin recovery middleware that logs panics via zap.
func zapRecovery(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("panic recovered",
					zap.Any("error", r),
					zap.String("path", c.Request.URL.Path),
					zap.String("method", c.Request.Method),
					zap.ByteString("stack", debug.Stack()),
				)
				c.AbortWithStatus(http.StatusInternalServerError)
			}
		}()
		c.Next()
	}
}
