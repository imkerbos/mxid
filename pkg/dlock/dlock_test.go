package dlock

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func newSQLite(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	return db
}

func TestRunAsLeader_SQLitePassthrough(t *testing.T) {
	db := newSQLite(t)
	ctx, cancel := context.WithCancel(context.Background())
	ran := make(chan struct{})
	go RunAsLeader(ctx, db, KeyAuditChainer, zap.NewNop(), func(c context.Context) {
		close(ran)
		<-c.Done()
	})
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("run never invoked on sqlite")
	}
	cancel()
	time.Sleep(50 * time.Millisecond)
}
