package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/middleware"
	"github.com/imkerbos/mxid/pkg/crypto"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// App holds all shared dependencies for the application.
type App struct {
	Config    *Config
	Logger    *zap.Logger
	DB        *gorm.DB
	Redis     *redis.Client
	Router    *gin.Engine
	EventBus  *event.Bus
	IDGen     *snowflake.Generator
	MasterKey *crypto.MasterKey

	// Route groups for domain module registration
	ConsoleGroup  *gin.RouterGroup
	PortalGroup   *gin.RouterGroup
	OpenAPIGroup  *gin.RouterGroup
	ProtocolGroup *gin.RouterGroup
}

// NewApp initializes all application dependencies.
func NewApp(configPath string) (*App, error) {
	// Load config
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	// Init logger
	logger, err := InitLogger(&cfg.Log)
	if err != nil {
		return nil, fmt.Errorf("init logger: %w", err)
	}

	// Init database
	db, err := InitDatabase(&cfg.Database, logger)
	if err != nil {
		return nil, fmt.Errorf("init database: %w", err)
	}

	// Run migrations
	if err := RunMigrations(&cfg.Database, logger); err != nil {
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	// Init Redis
	rdb, err := InitRedis(&cfg.Redis, logger)
	if err != nil {
		return nil, fmt.Errorf("init redis: %w", err)
	}

	// Init snowflake ID generator
	idGen, err := snowflake.New(cfg.Snowflake.NodeID)
	if err != nil {
		return nil, fmt.Errorf("init snowflake: %w", err)
	}

	// Init event bus
	eventBus := event.NewBus(logger)

	// Load master encryption key (fatal if missing or malformed — commercial-grade requirement)
	masterKey, err := crypto.NewMasterKey(cfg.Crypto.KeyEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("init master key (set MXID_CRYPTO_KEY_ENCRYPTION_KEY to base64(32 random bytes)): %w", err)
	}

	// Init router
	router := InitRouter(&cfg.Server, logger)

	// Resolve trusted-origins list. Single source of truth for both CORS
	// and CSRF so the two cannot drift apart.
	origins := cfg.Server.AllowedOrigins
	if len(origins) == 0 {
		origins = middleware.DefaultCORSConfig().AllowOrigins
	}

	// Apply shared middleware. CSRF is router-level (not per-group) with an
	// explicit skip-list — fail-safe: any new route is protected by default,
	// only the documented cross-origin surfaces (SSO protocol callbacks,
	// bearer-auth APIs, health probes) are opted out.
	router.Use(
		middleware.RequestID(),
		middleware.Logger(logger),
		middleware.CORS(middleware.CORSConfig{AllowOrigins: origins}),
		middleware.CSRF(middleware.CSRFConfig{
			TrustedOrigins: origins,
			SkipPaths: []string{
				"/protocol/", // OIDC/SAML/CAS receive RP POSTs cross-site by design
				"/openapi/",  // bearer-auth API tokens
				"/healthz",
				"/metrics",
			},
			AllowBearerAuth: true,
		}),
		// Global per-IP cap protects every endpoint from credential-
		// stuffing / brute force / scrapers. 600/min is comfortably
		// above any honest SPA usage but cuts off bulk automation.
		middleware.RateLimiter(rdb, middleware.RateLimitRule{
			Name: "ip", Limit: 600, Window: time.Minute,
			KeyFunc: middleware.KeyByClientIP,
		}),
	)

	// Register route groups
	consoleGroup, portalGroup, openapiGroup, protocolGroup := RegisterRouteGroups(router)

	app := &App{
		Config:        cfg,
		Logger:        logger,
		DB:            db,
		Redis:         rdb,
		Router:        router,
		EventBus:      eventBus,
		IDGen:         idGen,
		MasterKey:     masterKey,
		ConsoleGroup:  consoleGroup,
		PortalGroup:   portalGroup,
		OpenAPIGroup:  openapiGroup,
		ProtocolGroup: protocolGroup,
	}

	return app, nil
}

// Run starts the HTTP server with graceful shutdown.
func (a *App) Run() error {
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", a.Config.Server.Port),
		Handler:      a.Router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		a.Logger.Info("server starting",
			zap.Int("port", a.Config.Server.Port),
			zap.String("mode", a.Config.Server.Mode),
		)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-quit:
		a.Logger.Info("shutting down server...")
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	}

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}

	// Close resources
	a.cleanup()

	a.Logger.Info("server stopped")
	return nil
}

func (a *App) cleanup() {
	if sqlDB, err := a.DB.DB(); err == nil {
		sqlDB.Close()
	}
	a.Redis.Close()
	_ = a.Logger.Sync()
}
