package cas

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// CASServiceRef holds the data needed by SLO to send a back-channel
// logout request to a CAS service.
type CASServiceRef struct {
	ServiceURL string `json:"service_url"`
	Ticket     string `json:"ticket"`
}

// casSLORegistryTTL is the fixed TTL for service-registry entries.
// It must outlive the longest possible JIT grant (max 7 days) so that a
// later expiry or revocation can still find the service URL and send the
// SLO back-channel logout. Derived from ticket TTL would be wrong: the
// service-ticket TTL is O(seconds) while the session/grant can be 7 days.
const casSLORegistryTTL = 8 * 24 * time.Hour

// ServiceRegistry persists a per-user-per-app set of CAS services that
// a user has authenticated to. Task L5 reads this set to fan-out SLO
// logout requests.
//
// Storage: Redis SET keyed mxid:cas:svc:<userID>:<appID>.
// Each member is a JSON-encoded CASServiceRef. TTL on the set is
// refreshed on every RecordService call.
type ServiceRegistry struct {
	rdb *redis.Client
}

// NewServiceRegistry returns a ServiceRegistry backed by rdb.
func NewServiceRegistry(rdb *redis.Client) *ServiceRegistry {
	return &ServiceRegistry{rdb: rdb}
}

func casServiceKey(userID, appID int64) string {
	return fmt.Sprintf("mxid:cas:svc:%d:%d", userID, appID)
}

// casUserKey indexes the set of app IDs a user has authenticated to via CAS,
// so a global (portal/console) logout can enumerate every service to fan SLO
// out to — the per-(user,app) casServiceKey can't be reverse-scanned by user.
func casUserKey(userID int64) string {
	return fmt.Sprintf("mxid:cas:svc:user:%d", userID)
}

// RecordService notes that userID authenticated to serviceURL under ticket for
// the given app. The Redis SET TTL is reset to ttl so the entry ages out
// roughly when the underlying session would have expired.
func (r *ServiceRegistry) RecordService(ctx context.Context, userID, appID int64, serviceURL, ticket string, ttl time.Duration) error {
	ref, err := json.Marshal(CASServiceRef{ServiceURL: serviceURL, Ticket: ticket})
	if err != nil {
		return err
	}
	key := casServiceKey(userID, appID)
	userKey := casUserKey(userID)
	pipe := r.rdb.TxPipeline()
	pipe.SAdd(ctx, key, ref)
	pipe.Expire(ctx, key, ttl)
	// Mirror the app into the per-user index so global logout can find it.
	pipe.SAdd(ctx, userKey, appID)
	pipe.Expire(ctx, userKey, ttl)
	_, err = pipe.Exec(ctx)
	return err
}

// AppsForUser returns every app ID the user has an active CAS service session
// to. Used by global logout to fan SLO out across all CAS services.
func (r *ServiceRegistry) AppsForUser(ctx context.Context, userID int64) ([]int64, error) {
	members, err := r.rdb.SMembers(ctx, casUserKey(userID)).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}
	out := make([]int64, 0, len(members))
	for _, m := range members {
		var id int64
		if _, e := fmt.Sscanf(m, "%d", &id); e == nil && id != 0 {
			out = append(out, id)
		}
	}
	return out, nil
}

// ListServices returns all recorded service refs for userID+appID.
// Returns nil, nil when no entry exists.
func (r *ServiceRegistry) ListServices(ctx context.Context, userID, appID int64) ([]CASServiceRef, error) {
	members, err := r.rdb.SMembers(ctx, casServiceKey(userID, appID)).Result()
	if err != nil {
		return nil, err
	}
	out := make([]CASServiceRef, 0, len(members))
	for _, m := range members {
		var ref CASServiceRef
		if json.Unmarshal([]byte(m), &ref) == nil {
			out = append(out, ref)
		}
	}
	return out, nil
}

// Clear removes all service refs for userID+appID. Called on logout (L5). Also
// drops the app from the per-user index so a later global logout doesn't try
// to fan out to a service whose session is already gone.
func (r *ServiceRegistry) Clear(ctx context.Context, userID, appID int64) error {
	pipe := r.rdb.TxPipeline()
	pipe.Del(ctx, casServiceKey(userID, appID))
	pipe.SRem(ctx, casUserKey(userID), appID)
	_, err := pipe.Exec(ctx)
	return err
}
