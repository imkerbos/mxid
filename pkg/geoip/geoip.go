// Package geoip resolves an IP address to a city / country pair used by
// the audit pipeline. The package is intentionally tiny and dependency-
// free at this layer: callers wire either the bundled NoopResolver (the
// default — returns empties so audit rows still write) or a MaxMind
// GeoLite2 resolver from pkg/geoip/maxmind which keeps the heavy mmdb
// reader out of the binary when operators choose not to ship a db.
package geoip

import (
	"net"
	"strings"
)

// Location carries the resolved geo info. Empty strings on any field
// mean "unknown" — never substitute placeholders, the audit consumer
// downstream interprets empty as "unresolved".
type Location struct {
	Country string // ISO 3166-1 alpha-2 (e.g. "US", "CN")
	Region  string // first-level subdivision
	City    string
}

// Resolver is the narrow interface the audit pipeline depends on. A
// resolver MUST be safe for concurrent use — it sits behind a shared
// service and is hit on every audited request.
type Resolver interface {
	Lookup(ip string) (Location, error)
}

// NoopResolver returns empty Locations for every input. Use as the
// default when no GeoIP database is configured. Audit rows still
// persist; downstream UIs render "unknown".
type NoopResolver struct{}

func (NoopResolver) Lookup(string) (Location, error) { return Location{}, nil }

// PrivateAwareResolver wraps another resolver and short-circuits RFC1918
// / loopback addresses to an empty Location with no error. The MaxMind
// commercial DB returns no row for private space anyway; wrapping makes
// the contract explicit and avoids a wasted lookup on every internal
// request.
type PrivateAwareResolver struct {
	Inner Resolver
}

func (p PrivateAwareResolver) Lookup(ip string) (Location, error) {
	if IsPrivateOrLoopback(ip) {
		return Location{}, nil
	}
	if p.Inner == nil {
		return Location{}, nil
	}
	return p.Inner.Lookup(ip)
}

// IsPrivateOrLoopback reports whether the address is in an RFC1918,
// loopback, or link-local range. Used by the resolver wrapper above and
// available to callers that want to skip writing an "internal" geo row.
func IsPrivateOrLoopback(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return true
	}
	// Strip [v6]:port and v4:port shapes. SplitHostPort handles both
	// cleanly; on failure we treat the string as a bare IP.
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.Trim(raw, "[]")
	ip := net.ParseIP(raw)
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() || ip.IsUnspecified() {
		return true
	}
	return false
}
