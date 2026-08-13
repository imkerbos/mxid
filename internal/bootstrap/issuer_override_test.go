package bootstrap

import (
	"strings"
	"testing"
)

// MXID_ISSUER outranks server.issuer_url in ResolveBootIssuer, so validating
// the config field alone left the override unguarded.
//
// This is not a hypothetical env var: deploy/compose/docker-compose.dev.yml
// carries MXID_ISSUER=${MXID_ISSUER:-http://localhost:3500}, so a deployment
// derived from that file keeps a localhost issuer in release however carefully
// MXID_SERVER_ISSUER_URL was set.
//
// A localhost issuer is worse than a wrong one: it is the condition under which
// urlswap.SwapLocalhostHost substitutes the request's Host header, handing SAML
// EntityID and CAS service URLs to whoever sets that header.

func releaseConfigWithGoodIssuer() *Config {
	return &Config{
		Server: ServerConfig{
			Mode:           "release",
			AllowedOrigins: []string{"https://id.example.com"},
			IssuerURL:      "https://id.example.com",
		},
		Database: DatabaseConfig{Password: "a-real-password-not-on-the-deny-list"},
		Redis:    RedisConfig{Password: "a-real-redis-password"},
		Crypto: CryptoConfig{
			KeyEncryptionKey: "non-empty",
			AuditChainKey:    "non-empty",
			AuditAnchorKey:   "non-empty",
		},
		Session: SessionConfig{CookieSecure: true},
	}
}

func TestValidateSecrets_ReleaseRejectsLocalhostIssuerFromTheEnvOverride(t *testing.T) {
	for name, override := range map[string]string{
		"dev compose default": "http://localhost:3500",
		"loopback address":    "http://127.0.0.1:3500",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("MXID_ISSUER", override)

			cfg := releaseConfigWithGoodIssuer()
			err := cfg.validateSecrets()
			if err == nil {
				t.Fatalf("release mode started with an effective issuer of %q; server.issuer_url was "+
					"set correctly but MXID_ISSUER outranks it, so the running issuer is localhost and "+
					"the request Host header decides SAML EntityID and CAS service URLs", override)
			}
			if !strings.Contains(err.Error(), "MXID_ISSUER") {
				t.Fatalf("the error must name the variable actually at fault, got: %v", err)
			}
		})
	}
}

func TestValidateSecrets_ReleaseAcceptsARealEnvOverride(t *testing.T) {
	// The override exists for legitimate reasons; only a localhost value is
	// rejected.
	t.Setenv("MXID_ISSUER", "https://sso.example.com")

	cfg := releaseConfigWithGoodIssuer()
	if err := cfg.validateSecrets(); err != nil {
		t.Fatalf("a non-localhost MXID_ISSUER must be accepted, got %v", err)
	}
}

func TestValidateSecrets_ReleaseStillRejectsALocalhostConfigField(t *testing.T) {
	// The original check must keep working when no override is present.
	t.Setenv("MXID_ISSUER", "")

	cfg := releaseConfigWithGoodIssuer()
	cfg.Server.IssuerURL = "http://localhost:3500"
	if err := cfg.validateSecrets(); err == nil {
		t.Fatal("a localhost server.issuer_url must still fail in release")
	}
}
