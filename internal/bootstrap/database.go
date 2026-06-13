package bootstrap

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/imkerbos/mxid/pkg/tenantscope"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// InitDatabase creates a GORM database connection, auto-creating the database if it doesn't exist.
func InitDatabase(cfg *DatabaseConfig, logger *zap.Logger) (*gorm.DB, error) {
	// Auto-create database if not exists
	if err := ensureDatabase(cfg, logger); err != nil {
		return nil, fmt.Errorf("ensure database: %w", err)
	}

	logLevel := gormlogger.Warn
	switch cfg.LogLevel {
	case "silent":
		logLevel = gormlogger.Silent
	case "error":
		logLevel = gormlogger.Error
	case "warn":
		logLevel = gormlogger.Warn
	case "info":
		logLevel = gormlogger.Info
	}

	db, err := gorm.Open(postgres.Open(cfg.DSN()), &gorm.Config{
		Logger:                                   NewGormLogger(logger, logLevel),
		DisableForeignKeyConstraintWhenMigrating: true,
		PrepareStmt:                              true,
	})
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}

	// Secure-by-default multi-tenant isolation. The plugin auto-adds
	// `WHERE tenant_id = ?` (from the request's tenantscope) to every
	// Query/Update/Delete against a model implementing tenantscope.Tenanted,
	// and fails closed when a tenant-scoped model is touched without a scope.
	// Cross-tenant/system access requires an EXPLICIT escape
	// (tenantscope.SystemContext / WithCrossTenant). See pkg/tenantscope.
	if err := db.Use(tenantscope.NewPlugin()); err != nil {
		return nil, fmt.Errorf("install tenantscope plugin: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get sql.DB: %w", err)
	}

	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(time.Hour)
	sqlDB.SetConnMaxIdleTime(10 * time.Minute)

	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	logger.Info("database connected",
		zap.String("host", cfg.Host),
		zap.Int("port", cfg.Port),
		zap.String("database", cfg.Name),
	)

	return db, nil
}

// ensureDatabase connects to the default "postgres" database and creates the target database if it doesn't exist.
func ensureDatabase(cfg *DatabaseConfig, logger *zap.Logger) error {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable",
		cfg.Host, cfg.Port, cfg.User, cfg.Password,
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	defer db.Close()

	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", cfg.Name).Scan(&exists)
	if err != nil {
		return fmt.Errorf("check database exists: %w", err)
	}

	if !exists {
		// CREATE DATABASE doesn't support parameters, but cfg.Name is from config, not user input
		if _, err := db.Exec(fmt.Sprintf("CREATE DATABASE %q ENCODING 'UTF8'", cfg.Name)); err != nil {
			return fmt.Errorf("create database: %w", err)
		}
		logger.Info("database created", zap.String("name", cfg.Name))
	}

	return nil
}
