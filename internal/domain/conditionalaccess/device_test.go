package conditionalaccess

import (
	"context"
	"testing"
	"time"
)

// fakeDeviceRepo is an in-memory DeviceRepo for testing the service logic
// without a database.
type fakeDeviceRepo struct {
	rows    []*KnownDevice
	touched map[int64]int // id -> touch count
}

func newFakeRepo() *fakeDeviceRepo { return &fakeDeviceRepo{touched: map[int64]int{}} }

func (f *fakeDeviceRepo) Get(_ context.Context, userID int64, deviceID string) (*KnownDevice, error) {
	for _, d := range f.rows {
		if d.UserID == userID && d.DeviceID == deviceID {
			return d, nil
		}
	}
	return nil, nil
}
func (f *fakeDeviceRepo) Insert(_ context.Context, d *KnownDevice) error {
	f.rows = append(f.rows, d)
	return nil
}
func (f *fakeDeviceRepo) TouchLastSeen(_ context.Context, id int64, _ time.Time) error {
	f.touched[id]++
	return nil
}

type seqIDGen struct{ n int64 }

func (g *seqIDGen) Generate() int64 { g.n++; return g.n }

func TestDeviceService_IsKnown(t *testing.T) {
	repo := newFakeRepo()
	svc := NewDeviceService(repo, &seqIDGen{})
	ctx := context.Background()

	// Empty device id (no cookie) is never known.
	if known, _ := svc.IsKnown(ctx, 1, ""); known {
		t.Fatalf("empty device id must be unknown")
	}
	// Unseen device id is unknown.
	if known, _ := svc.IsKnown(ctx, 1, "dev-abc"); known {
		t.Fatalf("unseen device must be unknown")
	}
	// After Remember it becomes known — but only for that user.
	if err := svc.Remember(ctx, 1, 1, "dev-abc", "ua"); err != nil {
		t.Fatalf("remember: %v", err)
	}
	if known, _ := svc.IsKnown(ctx, 1, "dev-abc"); !known {
		t.Fatalf("remembered device must be known to user 1")
	}
	if known, _ := svc.IsKnown(ctx, 2, "dev-abc"); known {
		t.Fatalf("same device must be UNKNOWN to a different user")
	}
}

func TestDeviceService_RememberTouchesNotDuplicates(t *testing.T) {
	repo := newFakeRepo()
	svc := NewDeviceService(repo, &seqIDGen{})
	ctx := context.Background()

	_ = svc.Remember(ctx, 1, 1, "dev-x", "ua")
	_ = svc.Remember(ctx, 1, 1, "dev-x", "ua-updated")

	if len(repo.rows) != 1 {
		t.Fatalf("a re-seen device must not insert a second row, got %d", len(repo.rows))
	}
	if repo.touched[repo.rows[0].ID] != 1 {
		t.Fatalf("re-seen device must touch last_seen once, got %d", repo.touched[repo.rows[0].ID])
	}
}

func TestDeviceService_RememberEmptyIsNoop(t *testing.T) {
	repo := newFakeRepo()
	svc := NewDeviceService(repo, &seqIDGen{})
	if err := svc.Remember(context.Background(), 1, 1, "", "ua"); err != nil {
		t.Fatalf("empty remember: %v", err)
	}
	if len(repo.rows) != 0 {
		t.Fatalf("empty device id must not insert")
	}
}
