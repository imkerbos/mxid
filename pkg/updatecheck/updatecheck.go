// Package updatecheck implements the read-only "is there a newer MXID release"
// check behind the console's system/version page. It NEVER downloads or applies
// an update — applying an upgrade to a running IAM is a deliberate non-goal
// (see the deployment docs / update-feature evaluation). All it does is fetch a
// release manifest, compare SemVer, and cache the verdict.
//
// The outbound call goes through pkg/safehttp (the SSRF-safe client every
// server-side fetch must use). Results are cached in Redis so routine page
// loads don't hammer the GitHub API (60 req/h unauthenticated); a manual
// "check now" bypasses the cache.
package updatecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/mod/semver"

	"github.com/imkerbos/mxid/pkg/safehttp"
	"github.com/imkerbos/mxid/pkg/version"
)

const (
	cacheKey = "mxid:updatecheck:result"
	// releasesURL is the GitHub latest-release endpoint for this repo. Hardcoded
	// — MXID ships from one public repo, so there's nothing to configure.
	releasesURL = "https://api.github.com/repos/imkerbos/mxid/releases/latest"
	// cacheTTL is how long a result is reused before the next GET refetches.
	// Keeps routine page loads off the GitHub API (60 req/h unauthenticated);
	// the manual "check now" always bypasses it.
	cacheTTL = 6 * time.Hour
	// maxBody caps the release JSON we read so a hostile/huge manifest can't
	// balloon memory.
	maxBody = 1 << 20 // 1 MiB
)

// Release is the subset of a GitHub release we surface to the console.
type Release struct {
	Version     string `json:"version"`      // tag_name, e.g. v0.2.0
	Name        string `json:"name,omitempty"`
	URL         string `json:"url,omitempty"` // html_url — changelog / download page
	PublishedAt string `json:"published_at,omitempty"`
}

// Status is the full payload the console renders.
type Status struct {
	Current         version.Info `json:"current"`
	Latest          *Release     `json:"latest,omitempty"`
	UpdateAvailable bool         `json:"update_available"`
	CheckedAt       *time.Time   `json:"checked_at,omitempty"`
	// Error carries a human-readable reason the last check failed (network,
	// rate limit, no release yet). Non-empty Error does not break the page —
	// the current version still shows.
	Error string `json:"error,omitempty"`
}

// Checker performs and caches release checks.
type Checker struct {
	http *safehttp.Client
	rdb  *redis.Client
}

// cacheEntry is what we persist in Redis between checks.
type cacheEntry struct {
	Latest    *Release  `json:"latest,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
	Error     string    `json:"error,omitempty"`
}

// New builds a Checker. The safehttp client only permits https and re-checks
// every resolved IP, so the GitHub call can never be redirected to an internal
// address.
func New(rdb *redis.Client) *Checker {
	return &Checker{
		http: safehttp.New(safehttp.WithTimeout(10 * time.Second)),
		rdb:  rdb,
	}
}

// Status returns the current build identity plus the cached check result. If
// nothing is cached yet, it performs one live check to populate the cache.
func (c *Checker) Status(ctx context.Context) Status {
	if entry, ok := c.readCache(ctx); ok {
		return c.apply(entry)
	}
	return c.Check(ctx)
}

// Check forces a live fetch, refreshes the cache, and returns the result.
// Always safe to call (rate-limit / network errors are folded into Status.Error
// rather than returned), so the handler never 500s on a flaky upstream.
func (c *Checker) Check(ctx context.Context) Status {
	entry := cacheEntry{CheckedAt: time.Now().UTC()}
	rel, err := c.fetchLatest(ctx)
	if err != nil {
		entry.Error = err.Error()
	} else {
		entry.Latest = rel
	}
	c.writeCache(ctx, entry)
	return c.apply(entry)
}

// apply builds a Status from live build info + a cached check entry, recomputing
// the update flag.
func (c *Checker) apply(e cacheEntry) Status {
	st := Status{Current: version.Get()}
	st.Latest = e.Latest
	st.Error = e.Error
	t := e.CheckedAt
	st.CheckedAt = &t
	if e.Latest != nil {
		st.UpdateAvailable = isNewer(st.Current.Version, e.Latest.Version)
	}
	return st
}

// fetchLatest pulls the latest non-prerelease, non-draft release.
func (c *Checker) fetchLatest(ctx context.Context) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releasesURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "mxid-updatecheck")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reach release source: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// fall through
	case http.StatusNotFound:
		// Repo has no published release yet — treat as "no newer version",
		// not a hard error, so the page reads cleanly.
		return nil, nil
	case http.StatusForbidden, http.StatusTooManyRequests:
		return nil, fmt.Errorf("release source rate-limited, try again later")
	default:
		return nil, fmt.Errorf("release source returned %d", resp.StatusCode)
	}

	var payload struct {
		TagName     string `json:"tag_name"`
		Name        string `json:"name"`
		HTMLURL     string `json:"html_url"`
		PublishedAt string `json:"published_at"`
		Draft       bool   `json:"draft"`
		Prerelease  bool   `json:"prerelease"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode release: %w", err)
	}
	if payload.Draft || payload.Prerelease || payload.TagName == "" {
		return nil, nil
	}
	return &Release{
		Version:     payload.TagName,
		Name:        payload.Name,
		URL:         payload.HTMLURL,
		PublishedAt: payload.PublishedAt,
	}, nil
}

func (c *Checker) readCache(ctx context.Context) (cacheEntry, bool) {
	if c.rdb == nil {
		return cacheEntry{}, false
	}
	raw, err := c.rdb.Get(ctx, cacheKey).Bytes()
	if err != nil {
		return cacheEntry{}, false
	}
	var e cacheEntry
	if json.Unmarshal(raw, &e) != nil {
		return cacheEntry{}, false
	}
	return e, true
}

func (c *Checker) writeCache(ctx context.Context, e cacheEntry) {
	if c.rdb == nil {
		return
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return
	}
	_ = c.rdb.Set(ctx, cacheKey, raw, cacheTTL).Err()
}

// isNewer reports whether latest is a strictly greater SemVer than current.
// A non-SemVer current (e.g. "dev", a bare commit sha, or a "-dirty" describe)
// is treated as "not comparable" → no update is advertised, which is the safe
// default for unreleased local builds.
func isNewer(current, latest string) bool {
	current = ensureV(current)
	latest = ensureV(latest)
	if !semver.IsValid(current) || !semver.IsValid(latest) {
		return false
	}
	return semver.Compare(latest, current) > 0
}

func ensureV(s string) string {
	if s == "" {
		return s
	}
	if s[0] != 'v' {
		return "v" + s
	}
	return s
}
