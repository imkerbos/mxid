// Package urlswap provides the localhost-host swap used by every
// protocol handler when emitting user-facing redirects.
//
// The problem it solves: ops configures canonical URLs (issuer / portal /
// console) in either config.yaml or the runtime ExternalURLs setting.
// In dev and LAN-IP scenarios that canonical value is often
// "localhost:<port>" — useless to a browser on another host.
//
// SwapLocalhostHost takes the configured base URL and the inbound request
// Host header. When the configured host is localhost / 127.0.0.1 AND the
// inbound request arrived via a different host, it rewrites the base URL
// to use the inbound host (preserving the configured port — portal SPA
// usually runs on a different port than the backend in dev).
//
// In prod (canonical domain, real IP) the configured host already matches
// the inbound host, so the function is a no-op.
package urlswap

import (
	"context"
	"net/url"
	"strings"
)

// URLs groups the externally-reachable base URLs every protocol handler
// needs to construct redirects + metadata. Any field may be empty; the
// caller is expected to fall through to a static config value.
type URLs struct {
	Issuer  string
	Portal  string
	Console string
}

// Provider returns the runtime URLs. nil = no admin overrides; callers
// stick with the config defaults. Implementations are expected to read
// the ExternalURLs setting (which the admin can change at runtime) and
// merge with bootstrap config (where unset).
type Provider func(ctx context.Context) URLs

// Resolve merges admin-configured URLs (provider, if non-nil) with
// static defaults, then swaps localhost hosts to the inbound request
// host. Use this from every protocol handler that emits a user-facing
// redirect or builds discovery metadata.
//
// reqHost is the inbound Request.Host (may be empty for non-HTTP callers
// like a CLI building metadata; swap is then a no-op).
func Resolve(ctx context.Context, provider Provider, defaults URLs, reqHost string) URLs {
	out := defaults
	if provider != nil {
		p := provider(ctx)
		if p.Issuer != "" {
			out.Issuer = p.Issuer
		}
		if p.Portal != "" {
			out.Portal = p.Portal
		}
		if p.Console != "" {
			out.Console = p.Console
		}
	}
	out.Issuer = SwapLocalhostHost(out.Issuer, reqHost)
	out.Portal = SwapLocalhostHost(out.Portal, reqHost)
	out.Console = SwapLocalhostHost(out.Console, reqHost)
	return out
}

// SwapLocalhostHost rewrites base.Host to reqHost.Hostname when base
// points at localhost / 127.0.0.1. base.Port is preserved. Parse errors
// and non-localhost configurations return base unchanged.
//
// reqHost is the value of the inbound request's Host header (may include
// :port). The port portion is stripped before being applied.
func SwapLocalhostHost(base, reqHost string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	cfgHost := u.Hostname()
	if cfgHost != "localhost" && cfgHost != "127.0.0.1" {
		return base
	}
	if reqHost == "" {
		return base
	}
	if i := strings.IndexByte(reqHost, ':'); i > 0 {
		reqHost = reqHost[:i]
	}
	if reqHost == cfgHost {
		return base
	}
	if p := u.Port(); p != "" {
		u.Host = reqHost + ":" + p
	} else {
		u.Host = reqHost
	}
	return u.String()
}
