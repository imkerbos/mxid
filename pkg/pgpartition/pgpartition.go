// Package pgpartition manages the lifecycle of PostgreSQL RANGE partitions
// that are keyed on a timestamp and cut monthly.
//
// It exists because a declaratively partitioned table is only half a design:
// PostgreSQL will happily create the parent and the first partitions, then
// reject every INSERT once the ranges run out. That is not a slow degradation
// — it is a hard "no partition of relation found for row", and if the writer
// treats audit as best-effort the failure is silent.
//
// The manager owns three things, which together are the full contract:
//
//	Ensure         roll partitions forward so future writes always land
//	DropOlderThan  retention by dropping whole partitions, not deleting rows
//	DefaultRows    surveillance of the backstop partition
//
// # Why a DEFAULT partition, and why it must be watched
//
// A DEFAULT partition guarantees a write is never lost when pre-creation has
// failed. It is a backstop, NOT a landing zone: once rows for month M sit in
// DEFAULT, PostgreSQL refuses to create the partition for M —
//
//	ERROR: updated partition constraint for default partition would be
//	violated by some row
//
// — until those rows are moved out (see Adopt). So a non-empty DEFAULT is an
// operational alarm, not a normal state, and the alarm has to be visible or
// the table quietly wedges. That is why DefaultRows is part of the interface
// and is exported as a metric rather than being an internal detail.
//
// # Why dropping beats deleting
//
// A row-level DELETE on a time-partitioned table writes as much WAL as the
// original INSERT, leaves dead tuples for autovacuum, and never reclaims the
// space. Dropping a partition is a catalog operation. Measured on PostgreSQL
// 15 with 500k rows: DELETE 169ms and 82MB still resident, DROP 5.8ms with
// the space returned immediately.
package pgpartition

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"gorm.io/gorm"
)

// safeIdent guards every identifier that reaches a format string. The table
// name is developer-supplied rather than user input, but these strings are
// interpolated into DDL that cannot be parameterised, so the check is cheap
// insurance against a future caller passing something dynamic.
var safeIdent = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// Manager rolls monthly RANGE partitions for one parent table.
type Manager struct {
	db *gorm.DB
	// table is the partitioned parent, e.g. "mxid_audit_log".
	table string
	// ahead is how many future months to keep provisioned. It buys time for a
	// deployment whose scheduler is wedged: at 3, every partition needed for
	// the next quarter already exists.
	ahead int
}

// New builds a Manager. ahead is clamped to at least 1 — a value of 0 would
// provision only the current month and re-create the very cliff this package
// exists to remove.
func New(db *gorm.DB, table string, ahead int) (*Manager, error) {
	if !safeIdent.MatchString(table) {
		return nil, fmt.Errorf("pgpartition: unsafe table identifier %q", table)
	}
	if ahead < 1 {
		ahead = 1
	}
	return &Manager{db: db, table: table, ahead: ahead}, nil
}

// Table returns the parent table name, for logs and metric labels.
func (m *Manager) Table() string { return m.table }

// partitionName is the month partition naming convention, fixed by
// migration 000007 (mxid_audit_log_2026_08). Changing it would orphan every
// partition an existing deployment already has.
func (m *Manager) partitionName(month time.Time) string {
	return fmt.Sprintf("%s_%s", m.table, month.Format("2006_01"))
}

func (m *Manager) defaultName() string { return m.table + "_default" }

// monthStart truncates to the first instant of the month in UTC. Partition
// bounds are UTC because created_at is TIMESTAMPTZ: comparing in local time
// would shift boundaries under DST and produce ranges that neither abut nor
// cover.
func monthStart(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// Ensure creates any missing partition for the current month through
// `ahead` months out, plus the DEFAULT backstop. It is idempotent and safe to
// run on every replica, though callers normally run it under a leader lock to
// keep the logs quiet.
//
// Returns the partitions it created, newest last.
func (m *Manager) Ensure(ctx context.Context) ([]string, error) {
	var created []string

	// DEFAULT first: if this call is the one that races an insert past the end
	// of the provisioned range, the backstop should already be attached.
	if err := m.ensureDefault(ctx); err != nil {
		return created, err
	}

	start := monthStart(time.Now())
	for i := 0; i <= m.ahead; i++ {
		from := start.AddDate(0, i, 0)
		to := from.AddDate(0, 1, 0)
		name := m.partitionName(from)

		exists, err := m.relationExists(ctx, name)
		if err != nil {
			return created, err
		}
		if exists {
			continue
		}
		// Not CREATE TABLE IF NOT EXISTS: that swallows the useful error when a
		// differently-named partition already covers this range, which is a real
		// misconfiguration worth surfacing rather than skipping.
		sql := fmt.Sprintf(
			`CREATE TABLE %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')`,
			name, m.table,
			from.Format("2006-01-02 15:04:05-07"),
			to.Format("2006-01-02 15:04:05-07"),
		)
		if err := m.db.WithContext(ctx).Exec(sql).Error; err != nil {
			return created, fmt.Errorf("create partition %s: %w", name, err)
		}
		created = append(created, name)
	}
	return created, nil
}

func (m *Manager) ensureDefault(ctx context.Context) error {
	name := m.defaultName()
	exists, err := m.relationExists(ctx, name)
	if err != nil || exists {
		return err
	}
	sql := fmt.Sprintf(`CREATE TABLE %s PARTITION OF %s DEFAULT`, name, m.table)
	if err := m.db.WithContext(ctx).Exec(sql).Error; err != nil {
		return fmt.Errorf("create default partition %s: %w", name, err)
	}
	return nil
}

func (m *Manager) relationExists(ctx context.Context, name string) (bool, error) {
	var n int64
	err := m.db.WithContext(ctx).
		Raw(`SELECT count(*) FROM pg_class c
		     JOIN pg_namespace ns ON ns.oid = c.relnamespace
		     WHERE c.relname = ? AND ns.nspname = current_schema()`, name).
		Scan(&n).Error
	if err != nil {
		return false, fmt.Errorf("check relation %s: %w", name, err)
	}
	return n > 0, nil
}

// Partition describes one attached child partition and its bounds. Bounds are
// nil for the DEFAULT partition, which has none.
type Partition struct {
	Name      string
	From, To  *time.Time
	IsDefault bool
}

// List returns every attached partition of the parent, oldest first, with
// DEFAULT last. Bounds are read from the catalog rather than parsed out of the
// name, so a hand-created partition that does not follow the naming convention
// is still handled correctly.
func (m *Manager) List(ctx context.Context) ([]Partition, error) {
	type row struct {
		Name  string
		Bound string
	}
	var rows []row
	err := m.db.WithContext(ctx).
		Raw(`SELECT c.relname AS name, pg_get_expr(c.relpartbound, c.oid) AS bound
		     FROM pg_class p
		     JOIN pg_inherits i ON i.inhparent = p.oid
		     JOIN pg_class c ON c.oid = i.inhrelid
		     JOIN pg_namespace ns ON ns.oid = p.relnamespace
		     WHERE p.relname = ? AND ns.nspname = current_schema()
		     ORDER BY c.relname`, m.table).
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("list partitions of %s: %w", m.table, err)
	}

	out := make([]Partition, 0, len(rows))
	var def *Partition
	for _, r := range rows {
		p := Partition{Name: r.Name}
		if r.Bound == "DEFAULT" {
			p.IsDefault = true
			def = &p
			continue
		}
		from, to, ok := parseRangeBound(r.Bound)
		if !ok {
			// An unparseable bound must not be treated as droppable — skip it and
			// let a human look. Silently ignoring is safer than guessing, because
			// the caller uses this list to decide what to destroy.
			continue
		}
		p.From, p.To = &from, &to
		out = append(out, p)
	}
	if def != nil {
		out = append(out, *def)
	}
	return out, nil
}

// bound looks like: FOR VALUES FROM ('2026-08-01 00:00:00+00') TO ('2026-09-01 00:00:00+00')
var boundRe = regexp.MustCompile(`FROM \('([^']+)'\) TO \('([^']+)'\)`)

func parseRangeBound(bound string) (from, to time.Time, ok bool) {
	mt := boundRe.FindStringSubmatch(bound)
	if len(mt) != 3 {
		return from, to, false
	}
	const layout = "2006-01-02 15:04:05-07"
	f, err := time.Parse(layout, mt[1])
	if err != nil {
		return from, to, false
	}
	t, err := time.Parse(layout, mt[2])
	if err != nil {
		return from, to, false
	}
	return f, t, true
}

// DropOlderThan drops every partition whose range lies ENTIRELY before cutoff,
// and returns their names.
//
// Wholly-before is deliberate: a partition straddling the cutoff still holds
// rows that must be kept, so dropping it would destroy in-policy data. The
// consequence is that retention is granular to a month — data is kept for
// RetentionDays rounded up to the end of its month. That is the standard
// trade for partition-based retention, and the caller can still delete the
// straddling remainder by row if exactness matters.
//
// The DEFAULT partition is never dropped: it has no bounds, so it cannot be
// proven to be entirely out of policy, and it may be holding rows that only a
// human should dispose of.
func (m *Manager) DropOlderThan(ctx context.Context, cutoff time.Time) ([]string, error) {
	parts, err := m.List(ctx)
	if err != nil {
		return nil, err
	}
	var dropped []string
	for _, p := range parts {
		if p.IsDefault || p.To == nil {
			continue
		}
		if !p.To.After(cutoff) { // To <= cutoff  =>  whole range is older
			// DROP, not DETACH: the caller's contract is deletion. DETACH would
			// leave an orphan table consuming the same space with no owner.
			if err := m.db.WithContext(ctx).Exec(fmt.Sprintf(`DROP TABLE %s`, p.Name)).Error; err != nil {
				return dropped, fmt.Errorf("drop partition %s: %w", p.Name, err)
			}
			dropped = append(dropped, p.Name)
		}
	}
	return dropped, nil
}

// DefaultRows reports how many rows sit in the DEFAULT backstop. Zero is the
// only healthy value: anything else means pre-creation failed at some point,
// and that the partition for those rows' month can no longer be created until
// Adopt moves them out.
//
// Returns 0 when no DEFAULT partition exists.
func (m *Manager) DefaultRows(ctx context.Context) (int64, error) {
	name := m.defaultName()
	exists, err := m.relationExists(ctx, name)
	if err != nil || !exists {
		return 0, err
	}
	var n int64
	if err := m.db.WithContext(ctx).Raw(fmt.Sprintf(`SELECT count(*) FROM %s`, name)).Scan(&n).Error; err != nil {
		return 0, fmt.Errorf("count default partition %s: %w", name, err)
	}
	return n, nil
}

// Adopt un-wedges a table whose DEFAULT partition captured rows for month.
//
// It detaches DEFAULT, moves that month's rows into a real partition, and
// re-attaches — all in one transaction, so a failure anywhere leaves the table
// exactly as it was. This is the only supported way out of the state described
// in the package comment, and it is a deliberate manual operation rather than
// something the scheduler does on its own: it takes ACCESS EXCLUSIVE on the
// parent for the duration, which on a hot table is an outage, however brief.
//
// Measured on PostgreSQL 15: ~300ms to relocate 200k rows.
func (m *Manager) Adopt(ctx context.Context, month time.Time) (moved int64, err error) {
	from := monthStart(month)
	to := from.AddDate(0, 1, 0)
	name := m.partitionName(from)
	def := m.defaultName()

	exists, err := m.relationExists(ctx, name)
	if err != nil {
		return 0, err
	}
	if exists {
		return 0, fmt.Errorf("partition %s already exists; nothing to adopt", name)
	}

	const layout = "2006-01-02 15:04:05-07"
	fromS, toS := from.Format(layout), to.Format(layout)

	err = m.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(fmt.Sprintf(`ALTER TABLE %s DETACH PARTITION %s`, m.table, def)).Error; err != nil {
			return fmt.Errorf("detach default: %w", err)
		}
		if err := tx.Exec(fmt.Sprintf(`CREATE TABLE %s (LIKE %s INCLUDING ALL)`, name, m.table)).Error; err != nil {
			return fmt.Errorf("create %s: %w", name, err)
		}
		res := tx.Exec(fmt.Sprintf(
			`INSERT INTO %s SELECT * FROM %s WHERE created_at >= '%s' AND created_at < '%s'`,
			name, def, fromS, toS))
		if res.Error != nil {
			return fmt.Errorf("copy rows into %s: %w", name, res.Error)
		}
		moved = res.RowsAffected
		if err := tx.Exec(fmt.Sprintf(
			`DELETE FROM %s WHERE created_at >= '%s' AND created_at < '%s'`, def, fromS, toS)).Error; err != nil {
			return fmt.Errorf("clear moved rows from default: %w", err)
		}
		if err := tx.Exec(fmt.Sprintf(
			`ALTER TABLE %s ATTACH PARTITION %s FOR VALUES FROM ('%s') TO ('%s')`,
			m.table, name, fromS, toS)).Error; err != nil {
			return fmt.Errorf("attach %s: %w", name, err)
		}
		if err := tx.Exec(fmt.Sprintf(`ALTER TABLE %s ATTACH PARTITION %s DEFAULT`, m.table, def)).Error; err != nil {
			return fmt.Errorf("re-attach default: %w", err)
		}
		return nil
	})
	return moved, err
}
