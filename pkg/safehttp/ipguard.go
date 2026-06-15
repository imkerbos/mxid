package safehttp

import "net"

// blockedCIDRs are ranges the stdlib net.IP predicates (IsLoopback / IsPrivate
// / IsLinkLocal* / IsMulticast / IsUnspecified) do NOT cover but which an
// outbound server-side fetch must still never reach. Parsed once at init.
//
//   - 100.64.0.0/10   carrier-grade NAT / shared address space (RFC 6598) —
//                     heavily used for k8s node/pod CIDRs and cloud internal
//                     VIPs, so a prime SSRF target in this project's deploys.
//   - 192.0.0.0/24    IETF protocol assignments (incl. 192.0.0.171/.170 DNS64).
//   - 198.18.0.0/15   benchmarking (RFC 2544).
//   - 240.0.0.0/4     reserved / future use.
//   - 255.255.255.255/32  limited broadcast — never a valid fetch target.
//   - 2002::/16       6to4 — embeds an arbitrary IPv4 (see embeddedV4).
//   - 64:ff9b::/96    NAT64 well-known prefix — embeds an IPv4 (see embeddedV4).
//   - 64:ff9b:1::/48  NAT64 local-use prefix (RFC 8215).
//   - 2001:db8::/32   documentation.
//   - 2001::/23       IETF protocol assignments (Teredo 2001::/32 etc.).
var blockedCIDRs = func() []*net.IPNet {
	cidrs := []string{
		"100.64.0.0/10",
		"192.0.0.0/24",
		"198.18.0.0/15",
		"240.0.0.0/4",
		"255.255.255.255/32",
		"2002::/16",
		"64:ff9b::/96",
		"64:ff9b:1::/48",
		"2001:db8::/32",
		"2001::/23",
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("safehttp: bad blocked CIDR " + c + ": " + err.Error())
		}
		out = append(out, n)
	}
	return out
}()

// nat64WellKnown is 64:ff9b::/96; an address inside it carries a v4 dest in its
// last 4 bytes. Declared separately so embeddedV4 can extract it.
var nat64WellKnown = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("64:ff9b::/96")
	return n
}()

var sixToFour = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("2002::/16")
	return n
}()

// embeddedV4 returns the IPv4 address embedded in a 6to4 (2002:AABB:CCDD::/16)
// or NAT64 well-known (64:ff9b::/96) IPv6 address, or nil if none. These
// transition forms route to an arbitrary v4 destination — which can be an
// internal range — so the embedded address must be re-classified.
func embeddedV4(ip net.IP) net.IP {
	v6 := ip.To16()
	if v6 == nil || ip.To4() != nil {
		return nil
	}
	if sixToFour.Contains(ip) {
		// 2002:AABB:CCDD:: -> AA.BB.CC.DD (bytes 2..6 of the 16-byte form).
		return net.IPv4(v6[2], v6[3], v6[4], v6[5]).To4()
	}
	if nat64WellKnown.Contains(ip) {
		// 64:ff9b::WWXX:YYZZ -> W.X.Y.Z (last 4 bytes).
		return net.IPv4(v6[12], v6[13], v6[14], v6[15]).To4()
	}
	return nil
}

// isDisallowedIP reports whether ip is a destination an outbound server-side
// fetch must NOT be allowed to reach. It is the complete classifier (IPv4 and
// IPv6) and is deliberately self-contained rather than delegating to
// geoip.IsPrivateOrLoopback: that helper covers loopback / link-local-unicast
// / RFC1918+ULA / unspecified but does NOT reject multicast, CGNAT, transition
// ranges, or reserved space, which SSRF hardening requires. Keeping the full
// range list here makes the security control auditable in one place.
//
// Blocked ranges:
//
//   - unspecified            0.0.0.0          ::
//   - loopback               127.0.0.0/8      ::1
//   - private (RFC1918)      10/8 172.16/12 192.168/16
//   - unique-local IPv6      fc00::/7
//   - link-local unicast     169.254/16       fe80::/10
//   - link-local multicast / multicast / interface-local multicast
//   - carrier-grade NAT      100.64.0.0/10
//   - reserved / benchmark / proto-assignment / documentation  (see blockedCIDRs)
//   - broadcast              255.255.255.255
//   - IPv4-mapped IPv6       collapsed via To4() then re-checked
//   - 6to4 / NAT64           embedded v4 extracted and re-checked
//
// A nil ip is treated as disallowed (fail closed).
func isDisallowedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}

	// Collapse IPv4-mapped IPv6 (::ffff:a.b.c.d) to its v4 form so the v4
	// range checks below apply.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	if ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsPrivate() { // RFC1918 + IPv6 ULA fc00::/7
		return true
	}

	for _, n := range blockedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}

	// 6to4 / NAT64 carry an internal v4 destination inside an otherwise
	// public-looking v6 literal — re-classify the embedded address. (The
	// prefixes are already in blockedCIDRs as a belt-and-suspenders block,
	// but extraction also catches any future narrowing of those entries.)
	if v4 := embeddedV4(ip); v4 != nil && isDisallowedIP(v4) {
		return true
	}

	return false
}
