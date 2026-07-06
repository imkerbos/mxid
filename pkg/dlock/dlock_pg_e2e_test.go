package dlock

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestRunAsLeader_PGSingleLeader(t *testing.T) {
	dsn := os.Getenv("MXID_E2E_DSN")
	if dsn == "" {
		t.Skip("set MXID_E2E_DSN to a throwaway Postgres to run")
	}
	open := func() *gorm.DB {
		db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err != nil {
			t.Fatalf("open pg: %v", err)
		}
		return db
	}
	const key int64 = 0x11223344
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var active int32
	var maxActive int32
	work := func(c context.Context) {
		atomic.AddInt32(&active, 1)
		for {
			cur := atomic.LoadInt32(&active)
			if m := atomic.LoadInt32(&maxActive); cur > m {
				atomic.CompareAndSwapInt32(&maxActive, m, cur)
			}
			select {
			case <-c.Done():
				atomic.AddInt32(&active, -1)
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	go RunAsLeader(ctx, open(), key, zap.NewNop(), work)
	go RunAsLeader(ctx, open(), key, zap.NewNop(), work)

	time.Sleep(3 * time.Second)
	if got := atomic.LoadInt32(&maxActive); got != 1 {
		t.Fatalf("expected exactly 1 concurrent leader, saw max %d", got)
	}
	cancel()
	time.Sleep(500 * time.Millisecond)
}
