package oidcop

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// RevokeAllForClient is the containment lever for a leaked client secret.
// Nothing else covered it: RevokeToken is the RFC 7009 endpoint and needs the
// token string an operator does not have, TerminateSession covers one user, and
// the only remaining option was disabling the whole application.
//
// It depends on a reverse index (client → users) written by indexAdd, because
// the forward per-(user, client) sets cannot be enumerated by client without a
// SCAN over a keyspace shared with sessions and tickets, on a live instance,
// at the moment containment is most urgent. These tests pin the index and the revoke together, since an
// index that is not written makes the revoke silently a no-op: it would report
// success having deleted nothing, which is the worst possible outcome for a
// containment action.

func revokeStore(t *testing.T) (*Storage, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return NewStorage(rdb, nil, nil, nil, nil, nil, DefaultConfig()), rdb
}

func TestRevokeAllForClient_DropsEveryUsersTokens(t *testing.T) {
	s, rdb := revokeStore(t)
	ctx := context.Background()

	// Two users holding tokens for the affected client, one user holding a
	// token for a different client that must survive.
	s.indexAdd(ctx, "100", "client_bad", kToken("at-1"))
	s.indexAdd(ctx, "100", "client_bad", kRefresh("rt-1"))
	s.indexAdd(ctx, "200", "client_bad", kRefresh("rt-2"))
	s.indexAdd(ctx, "300", "client_good", kRefresh("rt-3"))
	for _, k := range []string{kToken("at-1"), kRefresh("rt-1"), kRefresh("rt-2"), kRefresh("rt-3")} {
		if err := rdb.Set(ctx, k, "{}", 0).Err(); err != nil {
			t.Fatal(err)
		}
	}

	n, err := s.RevokeAllForClient(ctx, "client_bad")
	if err != nil {
		t.Fatalf("RevokeAllForClient: %v", err)
	}
	if n != 2 {
		t.Errorf("revoked %d users, want 2", n)
	}

	for _, k := range []string{kToken("at-1"), kRefresh("rt-1"), kRefresh("rt-2")} {
		if ok, _ := rdb.Exists(ctx, k).Result(); ok != 0 {
			t.Errorf("token key %s survived the revoke", k)
		}
	}
	// The other client is untouched: this action is scoped to one app, and an
	// operator containing one leak must not log out every other integration.
	if ok, _ := rdb.Exists(ctx, kRefresh("rt-3")).Result(); ok != 1 {
		t.Error("a different client's token was revoked")
	}
	if ok, _ := rdb.Exists(ctx, kClientUsers("client_good")).Result(); ok != 1 {
		t.Error("a different client's user index was deleted")
	}
	if ok, _ := rdb.Exists(ctx, kClientUsers("client_bad")).Result(); ok != 0 {
		t.Error("the revoked client's user index was left behind")
	}
}

// indexAdd must write the reverse index on every token path, or the revoke
// quietly does nothing while reporting success.
func TestIndexAddWritesTheClientUserIndex(t *testing.T) {
	s, rdb := revokeStore(t)
	ctx := context.Background()

	s.indexAdd(ctx, "100", "client_abc", kRefresh("rt-1"))

	members, err := rdb.SMembers(ctx, kClientUsers("client_abc")).Result()
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || members[0] != "100" {
		t.Fatalf("client user index = %v, want [100]", members)
	}
	// TTL, not a permanent record of who ever used an app.
	ttl, err := rdb.TTL(ctx, kClientUsers("client_abc")).Result()
	if err != nil {
		t.Fatal(err)
	}
	if ttl <= 0 {
		t.Errorf("client user index TTL = %v, want the refresh-token lifetime", ttl)
	}
}

// Nothing to revoke is success, not an error: an operator containing a leak on
// an app with no live tokens must not see a failure.
func TestRevokeAllForClient_UnknownClientIsNotAnError(t *testing.T) {
	s, _ := revokeStore(t)
	n, err := s.RevokeAllForClient(context.Background(), "client_never_used")
	if err != nil {
		t.Fatalf("RevokeAllForClient: %v", err)
	}
	if n != 0 {
		t.Errorf("revoked %d, want 0", n)
	}
}

func TestRevokeAllForClient_EmptyClientIDIsANoop(t *testing.T) {
	s, rdb := revokeStore(t)
	ctx := context.Background()
	s.indexAdd(ctx, "100", "client_abc", kRefresh("rt-1"))

	n, err := s.RevokeAllForClient(ctx, "")
	if err != nil || n != 0 {
		t.Fatalf("RevokeAllForClient(\"\") = (%d, %v), want (0, nil)", n, err)
	}
	if ok, _ := rdb.Exists(ctx, kClientUsers("client_abc")).Result(); ok != 1 {
		t.Error("an empty client_id revoked something")
	}
}
