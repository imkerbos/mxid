package license

// Verification is the whole security boundary of the open-core split: if a token
// that should not verify does, every EE feature unlocks for free. It had 7.2%
// coverage, with verify, Load, IsEE, UserCap and Fingerprint all at zero.
//
// The embedded key's private half lives only in the vendor's license-authority
// repo, so these tests sign with their own pair and go through verifyWith /
// loadWith. What that cannot cover — that the *embedded* key is the right one —
// is not testable here by construction, and is asserted only to be well-formed.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// testKeys returns a deterministic pair, so a failure reproduces exactly.
func testKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

func otherKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(200 - i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

func mustSign(t *testing.T, priv ed25519.PrivateKey, p Payload) string {
	t.Helper()
	tok, err := Sign(priv, p)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

// signRaw bypasses Sign so a test can craft a payload Sign would normalise —
// specifically a wrong Product, which Sign always overwrites.
func signRaw(t *testing.T, priv ed25519.PrivateKey, p Payload) string {
	t.Helper()
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	seg := base64.RawURLEncoding.EncodeToString(body)
	sig := ed25519.Sign(priv, []byte(seg))
	return seg + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestVerifyAcceptsAWellFormedToken(t *testing.T) {
	pub, priv := testKeys(t)
	now := time.Unix(1_700_000_000, 0)
	tok := mustSign(t, priv, Payload{
		Customer:  "ACME",
		Features:  []Feature{FeatureExternalIDP},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(24 * time.Hour).Unix(),
		MaxUsers:  500,
	})

	p, err := verifyWith(pub, tok, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if p.Customer != "ACME" || p.MaxUsers != 500 || p.Product != Product {
		t.Fatalf("payload round-trip lost data: %+v", p)
	}
}

// The malformed cases all have to fail closed. A parser that fell through to
// "no signature to check" would accept anything.
func TestVerifyRejectsMalformedTokens(t *testing.T) {
	pub, priv := testKeys(t)
	now := time.Unix(1_700_000_000, 0)
	valid := mustSign(t, priv, Payload{Customer: "ACME"})
	parts := strings.Split(valid, ".")

	cases := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no separator", parts[0]},
		{"three segments", valid + "." + parts[1]},
		{"payload not base64url", "!!!." + parts[1]},
		{"signature not base64url", parts[0] + ".!!!"},
		{"payload not JSON", base64.RawURLEncoding.EncodeToString([]byte("not json")) + "." + parts[1]},
		{"empty segments", "."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := verifyWith(pub, c.token, now); err == nil {
				t.Fatal("token verified but must not have")
			}
		})
	}
}

// The one that matters most: a token signed by anyone other than the vendor.
func TestVerifyRejectsAForeignSignature(t *testing.T) {
	pub, _ := testKeys(t)
	_, foreignPriv := otherKeys(t)
	now := time.Unix(1_700_000_000, 0)

	tok := mustSign(t, foreignPriv, Payload{Customer: "ATTACKER", MaxUsers: 1_000_000})
	_, err := verifyWith(pub, tok, now)
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
}

// Editing the payload after signing must invalidate it — the signature covers
// the encoded payload segment, so this is the property that stops an operator
// from bumping their own MaxUsers.
func TestVerifyRejectsAnEditedPayload(t *testing.T) {
	pub, priv := testKeys(t)
	now := time.Unix(1_700_000_000, 0)
	tok := mustSign(t, priv, Payload{Customer: "ACME", MaxUsers: 10})
	sig := strings.Split(tok, ".")[1]

	tampered, err := json.Marshal(Payload{Product: Product, Customer: "ACME", MaxUsers: 10_000})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	edited := base64.RawURLEncoding.EncodeToString(tampered) + "." + sig

	if _, err := verifyWith(pub, edited, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
}

// A license signed for another product must not verify here even with a good
// signature — the guard that limits the blast radius of a shared-key leak.
func TestVerifyRejectsAnotherProduct(t *testing.T) {
	pub, priv := testKeys(t)
	now := time.Unix(1_700_000_000, 0)
	tok := signRaw(t, priv, Payload{Product: "someone-elses-product", Customer: "ACME"})

	if _, err := verifyWith(pub, tok, now); !errors.Is(err, ErrProduct) {
		t.Fatalf("err = %v, want ErrProduct", err)
	}
}

func TestVerifyExpiry(t *testing.T) {
	pub, priv := testKeys(t)
	exp := time.Unix(1_700_000_000, 0)

	t.Run("expired", func(t *testing.T) {
		tok := mustSign(t, priv, Payload{Customer: "ACME", ExpiresAt: exp.Unix()})
		if _, err := verifyWith(pub, tok, exp.Add(time.Second)); !errors.Is(err, ErrExpired) {
			t.Fatalf("err = %v, want ErrExpired", err)
		}
	})
	// The boundary is `now > exp`, so the expiry second itself is still valid.
	t.Run("exactly at expiry is still valid", func(t *testing.T) {
		tok := mustSign(t, priv, Payload{Customer: "ACME", ExpiresAt: exp.Unix()})
		if _, err := verifyWith(pub, tok, exp); err != nil {
			t.Fatalf("verify at the expiry second: %v", err)
		}
	})
	t.Run("perpetual never expires", func(t *testing.T) {
		tok := mustSign(t, priv, Payload{Customer: "ACME", ExpiresAt: 0})
		far := exp.Add(100 * 365 * 24 * time.Hour)
		if _, err := verifyWith(pub, tok, far); err != nil {
			t.Fatalf("perpetual license expired: %v", err)
		}
	})
}

// Install binding is what stops a license travelling with a copied DB dump.
func TestVerifyInstallBinding(t *testing.T) {
	pub, priv := testKeys(t)
	now := time.Unix(1_700_000_000, 0)
	const boundTo = "fingerprint-of-the-licensed-install"

	restore := InstallFingerprint()
	t.Cleanup(func() { SetInstallFingerprint(restore) })

	tok := mustSign(t, priv, Payload{Customer: "ACME", InstallID: boundTo})

	t.Run("matching install verifies", func(t *testing.T) {
		SetInstallFingerprint(boundTo)
		if _, err := verifyWith(pub, tok, now); err != nil {
			t.Fatalf("verify on the bound install: %v", err)
		}
	})
	t.Run("different install is refused", func(t *testing.T) {
		SetInstallFingerprint("some-other-install")
		if _, err := verifyWith(pub, tok, now); !errors.Is(err, ErrInstall) {
			t.Fatalf("err = %v, want ErrInstall", err)
		}
	})
	// Fail closed when the fingerprint has not been set yet (early boot): an
	// unset fingerprint must not read as "matches anything".
	t.Run("unset fingerprint is refused", func(t *testing.T) {
		SetInstallFingerprint("")
		if _, err := verifyWith(pub, tok, now); !errors.Is(err, ErrInstall) {
			t.Fatalf("err = %v, want ErrInstall", err)
		}
	})
	t.Run("an unbound license is portable", func(t *testing.T) {
		SetInstallFingerprint("whatever")
		portable := mustSign(t, priv, Payload{Customer: "ACME"})
		if _, err := verifyWith(pub, portable, now); err != nil {
			t.Fatalf("portable license refused: %v", err)
		}
	})
}

func TestLoad(t *testing.T) {
	pub, priv := testKeys(t)
	_, foreign := otherKeys(t)
	now := time.Unix(1_700_000_000, 0)

	t.Run("no token is clean CE", func(t *testing.T) {
		for _, tok := range []string{"", "   ", "\n\t"} {
			m := loadWith(pub, tok, now)
			if m.IsEE() || m.LoadErr() != nil || m.State() != "ce" {
				t.Fatalf("token %q: got EE=%v err=%v state=%q, want clean CE",
					tok, m.IsEE(), m.LoadErr(), m.State())
			}
		}
	})

	t.Run("a valid token is EE", func(t *testing.T) {
		tok := mustSign(t, priv, Payload{
			Customer: "ACME", MaxUsers: 250,
			ExpiresAt: now.Add(time.Hour).Unix(),
		})
		m := loadWith(pub, tok, now)
		if !m.IsEE() {
			t.Fatalf("valid token did not produce EE: err=%v", m.LoadErr())
		}
		if m.Edition() != EditionEE || m.State() != "ee" {
			t.Fatalf("edition=%q state=%q", m.Edition(), m.State())
		}
		if m.Customer() != "ACME" || m.MaxUsers() != 250 {
			t.Fatalf("customer=%q maxUsers=%d", m.Customer(), m.MaxUsers())
		}
		if got := m.ExpiresAt(); !got.Equal(now.Add(time.Hour)) {
			t.Fatalf("expiresAt = %v", got)
		}
	})

	// Every failure mode degrades to CE rather than erroring out of the boot
	// path, but LoadErr has to say which, because the console shows it.
	t.Run("failures degrade to CE with a reason", func(t *testing.T) {
		cases := []struct {
			name  string
			token string
			want  error
			state string
		}{
			{"malformed", "garbage", ErrMalformed, "invalid"},
			{"foreign signature", mustSign(t, foreign, Payload{Customer: "X"}), ErrSignature, "invalid"},
			{"wrong product", signRaw(t, priv, Payload{Product: "other"}), ErrProduct, "invalid"},
			{"expired", mustSign(t, priv, Payload{ExpiresAt: now.Add(-time.Hour).Unix()}), ErrExpired, "expired"},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				m := loadWith(pub, c.token, now)
				if m.IsEE() {
					t.Fatal("a failed license must not be EE")
				}
				if !errors.Is(m.LoadErr(), c.want) {
					t.Fatalf("LoadErr = %v, want %v", m.LoadErr(), c.want)
				}
				if m.State() != c.state {
					t.Fatalf("State = %q, want %q", m.State(), c.state)
				}
				if m.Edition() != EditionCE {
					t.Fatalf("Edition = %q, want ce", m.Edition())
				}
				if m.Has(FeatureExternalIDP) {
					t.Fatal("a failed license granted a feature")
				}
			})
		}
	})

	t.Run("install mismatch reports mismatch, not invalid", func(t *testing.T) {
		restore := InstallFingerprint()
		t.Cleanup(func() { SetInstallFingerprint(restore) })
		SetInstallFingerprint("this-install")

		tok := mustSign(t, priv, Payload{Customer: "ACME", InstallID: "another-install"})
		m := loadWith(pub, tok, now)
		if m.State() != "mismatch" {
			t.Fatalf("State = %q, want mismatch — the console distinguishes this from a forged token", m.State())
		}
	})
}

// UserCap decides whether new users can be created, so getting it wrong either
// blocks a paying customer or gives away unlimited seats.
func TestUserCap(t *testing.T) {
	cases := []struct {
		name string
		m    *Manager
		want int
	}{
		{"nil manager falls back to the CE cap", nil, CEMaxUsers},
		{"CE", CE(), CEMaxUsers},
		{"EE with no MaxUsers is unlimited", &Manager{valid: true, payload: &Payload{}}, 0},
		{"EE honours its MaxUsers", &Manager{valid: true, payload: &Payload{MaxUsers: 5000}}, 5000},
		// Expiry reverts to CE limits — existing data is grandfathered, but new
		// creation past the cap stops.
		{"expired reverts to the CE cap", &Manager{loadErr: ErrExpired, payload: &Payload{MaxUsers: 5000}}, CEMaxUsers},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.m.UserCap(); got != c.want {
				t.Fatalf("UserCap = %d, want %d", got, c.want)
			}
		})
	}
}

// A nil Manager is reachable before the license loads, so every accessor has to
// tolerate it rather than panicking the boot path.
func TestNilManagerIsSafe(t *testing.T) {
	var m *Manager
	if m.IsEE() {
		t.Error("nil manager reported EE")
	}
	if m.Edition() != EditionCE {
		t.Error("nil manager is not CE")
	}
	if m.State() != "ce" {
		t.Errorf("State = %q", m.State())
	}
	if m.Has(FeatureExternalIDP) {
		t.Error("nil manager granted a feature")
	}
	if m.EnabledFeatures() != nil {
		t.Error("nil manager listed features")
	}
	if m.Customer() != "" || m.MaxUsers() != 0 || m.LoadErr() != nil {
		t.Error("nil manager returned non-zero metadata")
	}
	if !m.ExpiresAt().IsZero() {
		t.Error("nil manager returned an expiry")
	}
}

// "EE = all implemented": a feature shipped after the license was issued must
// light up on binary upgrade, and the signed features[] list must not restrict.
func TestEnabledFeaturesIgnoresTheSignedSubset(t *testing.T) {
	pub, priv := testKeys(t)
	now := time.Unix(1_700_000_000, 0)
	tok := mustSign(t, priv, Payload{Customer: "ACME", Features: []Feature{FeatureBranding}})

	m := loadWith(pub, tok, now)
	got := m.EnabledFeatures()
	if len(got) != len(ImplementedFeatures) {
		t.Fatalf("EnabledFeatures = %v, want all %d implemented", got, len(ImplementedFeatures))
	}
	// Mutating the returned slice must not corrupt the package-level list.
	if len(got) > 0 {
		got[0] = "tampered"
		if ImplementedFeatures[0] == "tampered" {
			t.Fatal("EnabledFeatures handed out the backing array of ImplementedFeatures")
		}
	}
}

func TestFingerprint(t *testing.T) {
	const uuid = "11111111-2222-3333-4444-555555555555"

	base := Fingerprint(uuid, 7)
	if len(base) != 32 {
		t.Fatalf("fingerprint length = %d, want 32", len(base))
	}
	if base != Fingerprint(uuid, 7) {
		t.Fatal("fingerprint is not deterministic; every restart would invalidate bound licenses")
	}
	// Copying the DB to another cluster changes system_identifier — that is the
	// whole point of including it.
	if Fingerprint(uuid, 8) == base {
		t.Fatal("a different postgres system_identifier produced the same fingerprint")
	}
	if Fingerprint("99999999-2222-3333-4444-555555555555", 7) == base {
		t.Fatal("a different install UUID produced the same fingerprint")
	}
	// The separator stops (uuid, sysid) pairs from aliasing: without it,
	// ("ab", 1) and ("a", 21) would hash the same bytes... the '|' makes the
	// two inputs unambiguous.
	if Fingerprint("ab", 1) == Fingerprint("a", 21) {
		t.Fatal("concatenation is ambiguous — two different installs share a fingerprint")
	}
}

func TestInstallFingerprintAccessor(t *testing.T) {
	restore := InstallFingerprint()
	t.Cleanup(func() { SetInstallFingerprint(restore) })

	SetInstallFingerprint("")
	if got := InstallFingerprint(); got != "" {
		t.Fatalf("InstallFingerprint = %q, want empty", got)
	}
	SetInstallFingerprint("abc123")
	if got := InstallFingerprint(); got != "abc123" {
		t.Fatalf("InstallFingerprint = %q, want abc123", got)
	}
}

// The embedded key cannot be checked for correctness here — its private half is
// not in this repo — but a key that fails to decode would make every license
// fail at runtime with no local signal, so its shape is asserted.
func TestEmbeddedPublicKeyIsWellFormed(t *testing.T) {
	pub, err := publicKey()
	if err != nil {
		t.Fatalf("embedded public key does not load: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("embedded key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
}

// Sign is used by the vendor's signer, which imports this package precisely so
// the formats cannot drift. A round-trip is what proves they have not.
func TestSignRoundTripsThroughVerify(t *testing.T) {
	pub, priv := testKeys(t)
	now := time.Unix(1_700_000_000, 0)

	in := Payload{
		Product:   "ignored — Sign overwrites this",
		Customer:  "ACME GmbH",
		Features:  []Feature{FeatureExternalIDP, FeatureSCIM},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(365 * 24 * time.Hour).Unix(),
		MaxUsers:  1234,
		InstallID: "",
	}
	out, err := verifyWith(pub, mustSign(t, priv, in), now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if out.Product != Product {
		t.Fatalf("Sign did not stamp Product: %q", out.Product)
	}
	if out.Customer != in.Customer || out.MaxUsers != in.MaxUsers ||
		out.IssuedAt != in.IssuedAt || out.ExpiresAt != in.ExpiresAt ||
		len(out.Features) != len(in.Features) {
		t.Fatalf("round-trip mismatch:\n in = %+v\nout = %+v", in, out)
	}
}

// Current is what every gate in the app calls, and it must never hand back nil:
// a nil here would panic the gate rather than deny it, turning a licensing
// question into a 500 on an arbitrary request.
func TestCurrentIsNeverNil(t *testing.T) {
	restore := current.Load()
	t.Cleanup(func() { current.Store(restore) })

	current.Store(nil)
	if m := Current(); m == nil || m.IsEE() {
		t.Fatalf("unset Current() = %v, want a non-nil CE manager", m)
	}

	// SetCurrent(nil) is the runtime "license was removed" path; it must degrade
	// to CE rather than storing a nil that Current() then hands to a gate.
	SetCurrent(nil)
	if m := Current(); m == nil || m.IsEE() {
		t.Fatalf("SetCurrent(nil) then Current() = %v, want a non-nil CE manager", m)
	}

	SetCurrent(&Manager{valid: true, payload: &Payload{Customer: "ACME"}})
	if m := Current(); !m.IsEE() || m.Customer() != "ACME" {
		t.Fatalf("Current() did not return the installed manager: %+v", m)
	}
}

// Load is the exported entry point and goes through the embedded key, so only
// its non-signature branches are reachable here. They are the ones that run on
// every boot.
func TestLoadThroughTheEmbeddedKey(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	if m := Load("", now); m.IsEE() || m.LoadErr() != nil {
		t.Fatalf("empty token: EE=%v err=%v, want clean CE", m.IsEE(), m.LoadErr())
	}
	// Nothing in this repo can sign a token the embedded key accepts, which is
	// the property being asserted: a made-up token cannot unlock EE.
	if m := Load("bm90LWEtbGljZW5zZQ.c2ln", now); m.IsEE() {
		t.Fatal("a token not signed by the vendor unlocked EE")
	}
	if m := Load("garbage", now); !errors.Is(m.LoadErr(), ErrMalformed) {
		t.Fatalf("LoadErr = %v, want ErrMalformed", m.LoadErr())
	}
	pub, err := publicKey()
	if err != nil {
		t.Fatalf("publicKey: %v", err)
	}
	if _, err := verifyWith(pub, "garbage", now); !errors.Is(err, ErrMalformed) {
		t.Fatalf("verifyWith = %v, want ErrMalformed", err)
	}
}

// The two feature classifications answer different questions — "is it built"
// vs "does its code ship in the CE binary" — and conflating them is how a
// runtime-gated feature gets treated as absent (or vice versa).
func TestFeatureClassification(t *testing.T) {
	if !IsCodeSeparated(FeatureExternalIDP) {
		t.Error("external_idp ships only in the EE binary")
	}
	if IsCodeSeparated(FeatureBranding) {
		t.Error("branding is runtime-gated CE code, not code-separated")
	}
	if IsCodeSeparated("no-such-feature") {
		t.Error("an unknown key must not be reported as code-separated")
	}
	// Reserved-but-unbuilt keys must never be implemented, or a valid EE
	// licence would grant a feature that does not exist.
	for _, f := range []Feature{FeatureWebAuthn, FeatureSMS, FeatureAdvancedStepUp, FeatureMultiTenant} {
		if IsImplemented(f) {
			t.Errorf("%q is a reserved key and must not be implemented", f)
		}
	}
}
