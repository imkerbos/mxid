package portal

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// The portal's one-shot links — magic sign-in, password reset, email
// verification — must be consumed by a single atomic command.
//
// They used to read the token's entry and then delete it, two commands. Two
// requests carrying the same token can both finish their read before either
// delete lands, and both are honoured: two sessions from one magic link, two
// password sets from one reset link. The window needs the token and is narrow,
// so this is not a way in — but "one-shot" is the whole security property of
// these links, and the rest of the codebase already consumes single-use values
// with GETDEL (CAS service tickets, MFA challenges, the SSO confirmation token,
// external-IdP state). These three were the outliers.
//
// The assertion is on the command issued, not on a race. A concurrency test was
// written first and rejected: it passed against the two-command version too,
// because miniredis answers fast enough that the goroutines rarely interleave
// inside the window. A test that cannot fail against the defect is worse than
// none — it reports the property is held when nothing checks it.

// cmdRecorder captures the Redis commands a call issues.
type cmdRecorder struct {
	mu   sync.Mutex
	cmds []string
}

func (r *cmdRecorder) DialHook(next redis.DialHook) redis.DialHook { return next }

func (r *cmdRecorder) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		r.mu.Lock()
		r.cmds = append(r.cmds, strings.ToUpper(cmd.Name()))
		r.mu.Unlock()
		return next(ctx, cmd)
	}
}

func (r *cmdRecorder) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func (r *cmdRecorder) issued() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.cmds...)
}

func recordingRedis(t *testing.T) (*redis.Client, *cmdRecorder) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	rec := &cmdRecorder{}
	rdb.AddHook(rec)
	return rdb, rec
}

// assertAtomicConsume checks the consume path used one GETDEL and no separate
// DEL — a DEL means the read and the delete are still two commands.
func assertAtomicConsume(t *testing.T, rec *cmdRecorder, what string) {
	t.Helper()
	var getDel, del, get int
	for _, c := range rec.issued() {
		switch c {
		case "GETDEL":
			getDel++
		case "DEL":
			del++
		case "GET":
			get++
		}
	}
	if getDel != 1 || del != 0 || get != 0 {
		t.Fatalf("%s consumed with GET=%d DEL=%d GETDEL=%d (want GETDEL=1, no GET/DEL): "+
			"a read followed by a delete lets two requests carrying the same token both "+
			"pass the read before either delete lands, and both are honoured",
			what, get, del, getDel)
	}
}

func TestMagicLinkToken_ConsumedAtomically(t *testing.T) {
	rdb, rec := recordingRedis(t)
	ctx := context.Background()
	const token = "magic-token"
	if err := rdb.Set(ctx, magicLinkKeyPrefix+token, "7:1", 0).Err(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rec.cmds = nil // drop the seeding SET

	h := &MagicLinkHandler{rdb: rdb}
	if _, _, err := h.consumeToken(ctx, token); err != nil {
		t.Fatalf("consumeToken: %v", err)
	}
	assertAtomicConsume(t, rec, "magic link")

	// And it is genuinely gone.
	if _, _, err := h.consumeToken(ctx, token); err == nil {
		t.Fatal("the token survived its own consumption")
	}
}

func TestPasswordResetToken_ConsumedAtomically(t *testing.T) {
	rdb, rec := recordingRedis(t)
	ctx := context.Background()
	const token = "reset-token"
	if err := rdb.Set(ctx, pwdResetKeyPrefix+token, "1:7", 0).Err(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rec.cmds = nil

	h := &PasswordResetHandler{rdb: rdb}
	if _, _, err := h.consumeToken(ctx, token); err != nil {
		t.Fatalf("consumeToken: %v", err)
	}
	assertAtomicConsume(t, rec, "password reset")

	if _, _, err := h.consumeToken(ctx, token); err == nil {
		t.Fatal("the token survived its own consumption")
	}
}

func TestEmailVerifyToken_ConsumedAtomically(t *testing.T) {
	rdb, rec := recordingRedis(t)
	ctx := context.Background()
	const token = "verify-token"
	if err := rdb.Set(ctx, verifyKeyPrefix+token, "7:user@example.com", 0).Err(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rec.cmds = nil

	h := &EmailVerifyHandler{rdb: rdb}
	if _, _, err := h.consumeToken(ctx, token); err != nil {
		t.Fatalf("consumeToken: %v", err)
	}
	assertAtomicConsume(t, rec, "email verification")

	if _, _, err := h.consumeToken(ctx, token); err == nil {
		t.Fatal("the token survived its own consumption")
	}
}
