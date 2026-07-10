// Package dlock provides a Postgres advisory-lock based leader election so a
// single-writer background job runs on exactly one replica at a time, with
// automatic failover. On non-Postgres dialects it degrades to running the job
// directly (single-process dev/test).
package dlock

import (
	"context"
	"database/sql"
	"strconv"
	"time"

	"github.com/imkerbos/mxid/pkg/metrics"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

const (
	KeyAuditChainer  int64 = 0x4D5849440001
	KeyAuditAnchorer int64 = 0x4D5849440002
	KeyOIDCRotation  int64 = 0x4D5849440003
	KeyAccessSweeper int64 = 0x4D5849440004
	// KeyAuditRetention and KeyDynamicGroupReconcile gate the two periodic
	// sweepers to a single replica: retention runs a global cross-tenant purge
	// and dynamic-group reconcile rewrites membership, so running them on every
	// pod means redundant large DELETEs / cross-pod write races.
	KeyAuditRetention        int64 = 0x4D5849440005
	KeyDynamicGroupReconcile int64 = 0x4D5849440006
)

const retryInterval = 5 * time.Second

func RunAsLeader(ctx context.Context, db *gorm.DB, key int64, logger *zap.Logger, run func(ctx context.Context)) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if db.Dialector.Name() != "postgres" {
		run(ctx)
		return
	}
	sqlDB, err := db.DB()
	if err != nil {
		logger.Error("dlock: cannot get sql.DB", zap.Error(err))
		return
	}
	for {
		if ctx.Err() != nil {
			return
		}
		if err := leadOnce(ctx, sqlDB, key, logger, run); err != nil {
			logger.Warn("dlock: leadership loop error", zap.Int64("key", key), zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(retryInterval):
		}
	}
}

func leadOnce(ctx context.Context, sqlDB *sql.DB, key int64, logger *zap.Logger, run func(ctx context.Context)) error {
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	var got bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&got); err != nil {
		return err
	}
	if !got {
		select {
		case <-ctx.Done():
		case <-time.After(retryInterval):
		}
		return nil
	}
	logger.Info("dlock: acquired leadership", zap.Int64("key", key))
	keyLabel := strconv.FormatInt(key, 16)
	metrics.DlockLeader(keyLabel, true)
	defer metrics.DlockLeader(keyLabel, false)
	defer func() {
		_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", key)
	}()

	leaderCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		t := time.NewTicker(retryInterval)
		defer t.Stop()
		for {
			select {
			case <-leaderCtx.Done():
				return
			case <-t.C:
				// Independent deadline: under a gray failure (TCP session alive
				// but black-holed) a bare PingContext(leaderCtx) can block far
				// past the tick, so leaderCtx would never cancel and the standby
				// could not take over. Bound the probe so failover stays timely.
				pingCtx, pingCancel := context.WithTimeout(leaderCtx, retryInterval)
				err := conn.PingContext(pingCtx)
				pingCancel()
				if err != nil {
					logger.Warn("dlock: lock connection lost, stepping down", zap.Int64("key", key), zap.Error(err))
					cancel()
					return
				}
			}
		}
	}()

	run(leaderCtx)
	return nil
}
