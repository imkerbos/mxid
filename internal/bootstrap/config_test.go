package bootstrap

import (
	"strings"
	"testing"
)

func TestMaskedDSN_HidesPassword(t *testing.T) {
	cfg := &DatabaseConfig{
		Host: "db.example.com", Port: 5432, User: "mxid",
		Password: "supersecret", Name: "mxid",
	}
	masked := cfg.MaskedDSN()
	if strings.Contains(masked, "supersecret") {
		t.Errorf("MaskedDSN leaked password: %s", masked)
	}
	if !strings.Contains(masked, "password=***") {
		t.Errorf("MaskedDSN should contain placeholder, got %s", masked)
	}
}

func TestValidateSecrets_DebugModeAllowsPlaceholders(t *testing.T) {
	cfg := &Config{
		Server:   ServerConfig{Mode: "debug"},
		Database: DatabaseConfig{Password: "12345"},
	}
	if err := cfg.validateSecrets(); err != nil {
		t.Errorf("debug mode must permit placeholders, got %v", err)
	}
}

func TestValidateSecrets_ReleaseRejectsDevPassword(t *testing.T) {
	cases := []string{"", "12345", "password", "postgres", "admin", "root"}
	for _, pw := range cases {
		cfg := &Config{
			Server:   ServerConfig{Mode: "release"},
			Database: DatabaseConfig{Password: pw},
		}
		if err := cfg.validateSecrets(); err == nil {
			t.Errorf("release with password %q must fail", pw)
		}
	}
}

func TestValidateSecrets_ReleaseRejectsDevRedisPassword(t *testing.T) {
	cases := []string{"", "123456", "12345", "password", "admin"}
	for _, pw := range cases {
		cfg := &Config{
			Server:   ServerConfig{Mode: "release"},
			Database: DatabaseConfig{Password: "a-real-password-not-on-the-deny-list"},
			Redis:    RedisConfig{Password: pw},
			Crypto:   CryptoConfig{KeyEncryptionKey: "non-empty"},
			Session:  SessionConfig{CookieSecure: true},
		}
		if err := cfg.validateSecrets(); err == nil {
			t.Errorf("release with redis password %q must fail", pw)
		}
	}
}

func TestValidateSecrets_ReleaseRequiresKEK(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Mode:           "release",
			AllowedOrigins: []string{"https://id.example.com"},
			IssuerURL:      "https://id.example.com",
		},
		Database: DatabaseConfig{Password: "a-real-password-not-on-the-deny-list"},
		Redis:    RedisConfig{Password: "a-real-redis-password"},
		Session:  SessionConfig{CookieSecure: true},
	}
	if err := cfg.validateSecrets(); err == nil {
		t.Errorf("missing KEK must fail in release")
	}
	cfg.Crypto.KeyEncryptionKey = "non-empty"
	if err := cfg.validateSecrets(); err != nil {
		t.Errorf("release with all secrets set should pass, got %v", err)
	}
}

func TestValidateSecrets_ReleaseRequiresOriginsAndIssuer(t *testing.T) {
	base := func() *Config {
		return &Config{
			Server: ServerConfig{
				Mode:           "release",
				AllowedOrigins: []string{"https://id.example.com"},
				IssuerURL:      "https://id.example.com",
			},
			Database: DatabaseConfig{Password: "a-real-password-not-on-the-deny-list"},
			Redis:    RedisConfig{Password: "a-real-redis-password"},
			Session:  SessionConfig{CookieSecure: true},
			Crypto:   CryptoConfig{KeyEncryptionKey: "non-empty"},
		}
	}
	if err := base().validateSecrets(); err != nil {
		t.Fatalf("baseline release config should pass, got %v", err)
	}
	noOrigins := base()
	noOrigins.Server.AllowedOrigins = nil
	if err := noOrigins.validateSecrets(); err == nil {
		t.Errorf("empty allowed_origins must fail in release")
	}
	localIssuer := base()
	localIssuer.Server.IssuerURL = "http://localhost:10050"
	if err := localIssuer.validateSecrets(); err == nil {
		t.Errorf("localhost issuer_url must fail in release")
	}
}

func TestValidateSecrets_ReleaseRejectsLeakedKEK(t *testing.T) {
	cfg := &Config{
		Server:   ServerConfig{Mode: "release"},
		Database: DatabaseConfig{Password: "a-real-password-not-on-the-deny-list"},
		Redis:    RedisConfig{Password: "a-real-redis-password"},
		Crypto:   CryptoConfig{KeyEncryptionKey: "XH76Q0Vwe81cFhXaML+fWrvAffwQCp2bwUMRofcosfI="},
		Session:  SessionConfig{CookieSecure: true},
	}
	if err := cfg.validateSecrets(); err == nil {
		t.Errorf("a KEK that leaked into git history must fail in release")
	}
}

func TestValidateSecrets_ReleaseRequiresCookieSecure(t *testing.T) {
	cfg := &Config{
		Server:   ServerConfig{Mode: "release"},
		Database: DatabaseConfig{Password: "a-real-password-not-on-the-deny-list"},
		Redis:    RedisConfig{Password: "a-real-redis-password"},
		Crypto:   CryptoConfig{KeyEncryptionKey: "non-empty"},
		Session:  SessionConfig{CookieSecure: false},
	}
	if err := cfg.validateSecrets(); err == nil {
		t.Errorf("CookieSecure=false in release must fail")
	}
}
