package authn

import (
	"context"
	"crypto/rand"
	"math/big"
	"strings"
	"time"

	"github.com/mojocn/base64Captcha"
	"github.com/redis/go-redis/v9"

	"github.com/imkerbos/mxid/pkg/ratelimit"
)

const (
	captchaKeyPrefix = "mxid:captcha:"
	captchaTTL       = 5 * time.Minute

	// captchaCharset is the answer alphabet. Pure digits (the old driver) are
	// close to free for commodity OCR, so this mixes digits and letters while
	// dropping every confusable pair a human would mistype — 0/O/Q, 1/I/J/L,
	// 2/Z, 5/S, 6/G, 8/B. 22 glyphs, one case only: the extra glyphs raise the
	// per-character OCR error rate, which is what compounds over the answer.
	captchaCharset = "34792ACDEFHKMNPRTUVWXY"

	// captchaLength is 6, up from 5. Automated solve rate is per-character
	// accuracy to the power of the length, so one more character is a
	// multiplicative win; 6 glyphs across 240px still leaves ~40px each.
	captchaLength = 6

	// captchaNoiseCount is 2, and no higher, because DriverString draws noise as
	// whole extra glyphs rather than the digit driver's dots — noise competes
	// with the answer for legibility instead of merely dirtying the background.
	// The two size ranges genuinely overlap (answer 35-65px deep-coloured, noise
	// 25-45px light-coloured), so a small answer glyph and a large noise glyph
	// are not reliably distinguishable. The first and last positions pay for
	// that: an interior glyph can be recognised as part of the answer by lining
	// up with its neighbours, an edge glyph has nothing to line up with, and
	// sampled images had edge characters read as noise and dropped.
	//
	// Two is still enough to break a naive "slice into six equal cells"
	// pipeline, which is all the noise is here to do.
	captchaNoiseCount = 2
)

// captchaIssueLimit bounds how many captchas a single IP may be issued.
// Pre-fetching a large batch and solving it offline is the way around
// single-use consumption, and the generic 1200/min per-IP ceiling is far too
// loose to stop it. 20 per 5 minutes is well above honest reload behaviour.
var captchaIssueLimit = ratelimit.Config{
	Purpose:     "captcha_issue",
	MaxAttempts: 20,
	Window:      5 * time.Minute,
	Lockout:     10 * time.Minute,
	FailOpen:    false,
}

// captchaFonts are the subset of the embedded faces that stay legible to a
// human. Varying the face per image denies an attacker a single glyph
// template to match against.
var captchaFonts = []string{"chromohv.ttf", "RitaSmith.ttf", "3Dumb.ttf"}

// CaptchaResponse is the API response for captcha generation.
type CaptchaResponse struct {
	CaptchaID    string `json:"captcha_id"`
	CaptchaImage string `json:"captcha_image"`
}

// redisCaptchaStore implements base64Captcha.Store backed by Redis.
type redisCaptchaStore struct {
	rdb *redis.Client
}

func (s *redisCaptchaStore) Set(id string, value string) error {
	return s.rdb.Set(context.Background(), captchaKeyPrefix+id, value, captchaTTL).Err()
}

func (s *redisCaptchaStore) Get(id string, clear bool) string {
	key := captchaKeyPrefix + id
	val, err := s.rdb.Get(context.Background(), key).Result()
	if err != nil {
		return ""
	}
	if clear {
		s.rdb.Del(context.Background(), key)
	}
	return val
}

func (s *redisCaptchaStore) Verify(id, answer string, clear bool) bool {
	answer = strings.TrimSpace(answer)
	// Reject before touching the store: a blank answer can only ever match a
	// blank stored value, and a blank stored value is a miss, not a secret.
	if answer == "" {
		return false
	}
	stored := strings.TrimSpace(s.Get(id, clear))
	if stored == "" {
		return false
	}
	// Case-insensitive: the charset is mixed digits+letters now, and making a
	// human reproduce the case of a warped glyph is a UX tax that buys an
	// attacker's OCR nothing. Both sides are known non-empty here, so EqualFold
	// cannot turn a store miss into a match.
	return strings.EqualFold(stored, answer)
}

// CaptchaService handles captcha generation and verification.
type CaptchaService struct {
	driver       *base64Captcha.DriverString
	store        *redisCaptchaStore
	issueLimiter *ratelimit.Limiter
}

// NewCaptchaService creates a new captcha service backed by Redis.
func NewCaptchaService(rdb *redis.Client) *CaptchaService {
	store := &redisCaptchaStore{rdb: rdb}
	driver := base64Captcha.NewDriverString(
		80, 240, captchaNoiseCount,
		// No decorative lines (the option field is a bitmask; 0 = none). All
		// three — hollow, slime, sine — pick their thickness, amplitude and
		// period from the library's own randomness, so their worst case is not
		// something we can bound: sampled images had a glyph clipped or buried
		// under the band.
		//
		// Dropping them costs little, because a line does not stop automation.
		// An image captcha is transparent to commercial solving services; it is
		// a speed bump, and the controls that actually hold are per-account
		// throttling and the issuance limit below. So readability wins: one
		// fewer flourish beats one more human typing it wrong.
		0,
		captchaLength, captchaCharset, nil, nil, captchaFonts,
	)
	// Errors here only mean a nil client or empty purpose; a nil Limiter is a
	// valid "no limit", so the service stays usable either way.
	limiter, _ := ratelimit.New(rdb, captchaIssueLimit)
	return &CaptchaService{driver: driver, store: store, issueLimiter: limiter}
}

// randomAnswer draws the answer from a CSPRNG. The library's DriverString gets
// its text from RandText, which uses math/rand — fine for the noise glyphs it
// was written for, not for the secret itself. rand.Int takes a modulus rather
// than a byte, so a 22-glyph (non-power-of-two) charset carries no modulo bias.
func randomAnswer() (string, error) {
	limit := big.NewInt(int64(len(captchaCharset)))
	out := make([]byte, captchaLength)
	for i := range out {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		out[i] = captchaCharset[n.Int64()]
	}
	return string(out), nil
}

// Generate creates a new captcha and returns the ID and base64 image. It is
// the unlimited primitive — callers serving an HTTP request must use
// GenerateFor so issuance is bounded per client.
//
// It deliberately bypasses base64Captcha.Captcha.Generate, whose only extra
// work is picking the answer with math/rand. The id still comes from the
// library's RandomId, which reads crypto/rand (randomBytesMod).
func (s *CaptchaService) Generate() (*CaptchaResponse, error) {
	answer, err := randomAnswer()
	if err != nil {
		return nil, err
	}
	item, err := s.driver.DrawCaptcha(answer)
	if err != nil {
		return nil, err
	}
	id := base64Captcha.RandomId()
	// Stored before the image reaches the caller: a captcha we cannot verify
	// later must never be answerable.
	if err := s.store.Set(id, answer); err != nil {
		return nil, err
	}
	return &CaptchaResponse{
		CaptchaID:    id,
		CaptchaImage: item.EncodeB64string(),
	}, nil
}

// GenerateFor issues a captcha for one client, counting the issuance against
// that client's budget. It returns a *ratelimit.RateLimitError (matching
// ratelimit.ErrRateLimited, carrying RetryAfter) once the budget is spent, so
// the caller can answer 429 instead of handing out more puzzles to pre-solve.
func (s *CaptchaService) GenerateFor(ctx context.Context, clientIP string) (*CaptchaResponse, error) {
	if err := s.issueLimiter.Check(ctx, clientIP); err != nil {
		return nil, err
	}
	resp, err := s.Generate()
	if err != nil {
		return nil, err
	}
	// Counted after the fact: a failed generation should not spend the budget.
	// The returned lock is ignored — this request already earned its captcha;
	// the next one is the one that gets refused.
	_ = s.issueLimiter.RecordFailure(ctx, clientIP)
	return resp, nil
}

// Verify checks if the provided answer matches the captcha. It deliberately
// bypasses base64Captcha.Captcha.Verify, which trims both sides and then
// compares, so a whitespace-only answer matched a store miss ("" == "") and
// passed. The store's own Verify fails closed on an empty answer or value.
func (s *CaptchaService) Verify(id, answer string) bool {
	return s.store.Verify(id, answer, true)
}
