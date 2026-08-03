package pgpartition

// Postgres end-to-end tests. Skipped unless MXID_E2E_DSN points at a THROWAWAY
// database — every case creates and drops its own partitioned table.
//
// These cannot be unit tests: the whole package is DDL whose behaviour lives in
// PostgreSQL, not in Go. The interesting case in particular — that a DEFAULT
// partition holding rows makes CREATE ... PARTITION OF fail — has no analogue
// in sqlite and would be invented, not tested, by a mock.

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("MXID_E2E_DSN")
	if dsn == "" {
		t.Skip("set MXID_E2E_DSN to run pgpartition e2e tests (throwaway DB only)")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return db
}

// newParent creates a uniquely-named partitioned table so parallel packages
// and repeated runs never collide.
func newParent(t *testing.T, db *gorm.DB) string {
	t.Helper()
	name := fmt.Sprintf("pt_%d", time.Now().UnixNano()%1_000_000_000)
	err := db.Exec(fmt.Sprintf(`
		CREATE TABLE %s (
			id         BIGINT      NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			payload    TEXT,
			PRIMARY KEY (id, created_at)
		) PARTITION BY RANGE (created_at)`, name)).Error
	if err != nil {
		t.Fatalf("create parent: %v", err)
	}
	t.Cleanup(func() { db.Exec(fmt.Sprintf(`DROP TABLE IF EXISTS %s CASCADE`, name)) })
	return name
}

func insertAt(t *testing.T, db *gorm.DB, table string, id int64, at time.Time) error {
	t.Helper()
	return db.Exec(fmt.Sprintf(`INSERT INTO %s (id, created_at, payload) VALUES (?, ?, 'x')`, table),
		id, at).Error
}

func TestEnsureCreatesCurrentAndAheadMonthsAndIsIdempotent(t *testing.T) {
	db := testDB(t)
	parent := newParent(t, db)
	m, err := New(db, parent, 3)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx := context.Background()

	created, err := m.Ensure(ctx)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	// current month + 3 ahead
	if len(created) != 4 {
		t.Fatalf("first Ensure created %d partitions, want 4: %v", len(created), created)
	}

	// Second pass must be a no-op — the scheduler runs this every few hours and
	// must not churn DDL or log noise.
	again, err := m.Ensure(ctx)
	if err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("second Ensure created %v, want none", again)
	}

	// A write three months out must land, which is the entire point.
	future := monthStart(time.Now()).AddDate(0, 3, 15)
	if err := insertAt(t, db, parent, 1, future); err != nil {
		t.Fatalf("insert %s: %v", future.Format(time.RFC3339), err)
	}
}

func TestDefaultPartitionCatchesBeyondHorizonAndIsReported(t *testing.T) {
	db := testDB(t)
	parent := newParent(t, db)
	m, _ := New(db, parent, 1)
	ctx := context.Background()

	if _, err := m.Ensure(ctx); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	// Far outside the provisioned horizon: without a DEFAULT this INSERT is the
	// production failure this package exists to prevent.
	far := monthStart(time.Now()).AddDate(0, 10, 5)
	if err := insertAt(t, db, parent, 2, far); err != nil {
		t.Fatalf("insert beyond horizon should be caught by DEFAULT, got: %v", err)
	}

	n, err := m.DefaultRows(ctx)
	if err != nil {
		t.Fatalf("default rows: %v", err)
	}
	if n != 1 {
		t.Fatalf("DefaultRows = %d, want 1 — the alarm that says pre-creation fell behind", n)
	}
}

// The behaviour that makes DEFAULT a trap rather than a free safety net, and
// the recovery path out of it.
func TestDefaultRowsBlockPartitionCreationUntilAdopted(t *testing.T) {
	db := testDB(t)
	parent := newParent(t, db)
	m, _ := New(db, parent, 1)
	ctx := context.Background()
	if _, err := m.Ensure(ctx); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	stuck := monthStart(time.Now()).AddDate(0, 6, 10)
	if err := insertAt(t, db, parent, 3, stuck); err != nil {
		t.Fatalf("seed default: %v", err)
	}

	// PostgreSQL now refuses to create that month's partition, because rows in
	// DEFAULT would violate its new constraint.
	name := m.partitionName(monthStart(stuck))
	err := db.Exec(fmt.Sprintf(
		`CREATE TABLE %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')`,
		name, parent,
		monthStart(stuck).Format("2006-01-02 15:04:05-07"),
		monthStart(stuck).AddDate(0, 1, 0).Format("2006-01-02 15:04:05-07"))).Error
	if err == nil {
		t.Fatal("expected partition creation to fail while DEFAULT holds that month's rows")
	}

	// Adopt is the way out.
	moved, err := m.Adopt(ctx, stuck)
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if moved != 1 {
		t.Fatalf("Adopt moved %d rows, want 1", moved)
	}

	n, err := m.DefaultRows(ctx)
	if err != nil {
		t.Fatalf("default rows after adopt: %v", err)
	}
	if n != 0 {
		t.Fatalf("DEFAULT still holds %d rows after Adopt", n)
	}

	// The row survived the move and is now in a real partition.
	var got int64
	if err := db.Raw(fmt.Sprintf(`SELECT count(*) FROM %s`, name)).Scan(&got).Error; err != nil {
		t.Fatalf("count adopted partition: %v", err)
	}
	if got != 1 {
		t.Fatalf("adopted partition holds %d rows, want 1", got)
	}

	// And Ensure keeps working afterwards.
	if _, err := m.Ensure(ctx); err != nil {
		t.Fatalf("ensure after adopt: %v", err)
	}
}

func TestDropOlderThanDropsOnlyWhollyExpiredPartitions(t *testing.T) {
	db := testDB(t)
	parent := newParent(t, db)
	m, _ := New(db, parent, 0)
	ctx := context.Background()
	if _, err := m.Ensure(ctx); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	// Three past months, attached by hand so the test controls the bounds.
	base := monthStart(time.Now())
	for i := 3; i >= 1; i-- {
		from := base.AddDate(0, -i, 0)
		to := from.AddDate(0, 1, 0)
		err := db.Exec(fmt.Sprintf(
			`CREATE TABLE %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')`,
			m.partitionName(from), parent,
			from.Format("2006-01-02 15:04:05-07"), to.Format("2006-01-02 15:04:05-07"))).Error
		if err != nil {
			t.Fatalf("create past partition: %v", err)
		}
	}

	// Cutoff mid-way through the month that starts 2 months ago: that partition
	// straddles the cutoff and MUST survive, because it still holds in-policy
	// rows. Only the month before it is wholly expired.
	cutoff := base.AddDate(0, -2, 0).Add(15 * 24 * time.Hour)
	dropped, err := m.DropOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("drop: %v", err)
	}
	if len(dropped) != 1 {
		t.Fatalf("dropped %v, want exactly the one wholly-expired partition", dropped)
	}
	if want := m.partitionName(base.AddDate(0, -3, 0)); dropped[0] != want {
		t.Fatalf("dropped %q, want %q", dropped[0], want)
	}

	// The straddling partition is still attached and still accepts reads.
	straddling := m.partitionName(base.AddDate(0, -2, 0))
	var n int64
	if err := db.Raw(fmt.Sprintf(`SELECT count(*) FROM %s`, straddling)).Scan(&n).Error; err != nil {
		t.Fatalf("straddling partition should survive the cutoff: %v", err)
	}
}

func TestDropOlderThanNeverDropsDefault(t *testing.T) {
	db := testDB(t)
	parent := newParent(t, db)
	m, _ := New(db, parent, 0)
	ctx := context.Background()
	if _, err := m.Ensure(ctx); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	// Far future cutoff: everything bounded is expired. DEFAULT has no bounds,
	// so it cannot be proven expired and must be left for a human.
	if _, err := m.DropOlderThan(ctx, time.Now().AddDate(10, 0, 0)); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if _, err := m.DefaultRows(ctx); err != nil {
		t.Fatalf("DEFAULT should still exist after a sweeping drop: %v", err)
	}
}

func TestNewRejectsUnsafeIdentifier(t *testing.T) {
	// No DB needed — this is the guard on identifiers reaching DDL string
	// interpolation, which cannot be parameterised.
	for _, bad := range []string{`t; DROP TABLE users`, `"quoted"`, `Table`, ``, `1t`} {
		if _, err := New(nil, bad, 1); err == nil {
			t.Errorf("New(%q) accepted an unsafe identifier", bad)
		}
	}
	if _, err := New(nil, "mxid_audit_log", 1); err != nil {
		t.Errorf("New rejected a valid identifier: %v", err)
	}
}
