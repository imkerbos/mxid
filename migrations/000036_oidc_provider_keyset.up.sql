-- Provider-level OIDC signing keyset.
--
-- Unlike SAML (one signing cert per app, in mxid_app_cert), OIDC has a single
-- issuer with a single logical keyset shared by ALL clients — the OIDC/OAuth
-- model every major IdP follows (Okta authorization-server, Auth0 tenant,
-- Keycloak realm, zitadel instance). Per-client signing keys are an anti-pattern:
-- the key identifies the *issuer*, not the client, and per-client `aud` already
-- scopes a token to its client. Decoupling OIDC keys from the per-app SAML cert
-- table also means a key rotation touches ONE keyset, not N app certs.
--
-- Rotation model (same lifecycle as mxid_app_cert): exactly one ACTIVE key signs
-- new tokens; rotating it demotes the previous active to ROTATING so its public
-- key stays in the JWKS until tokens it signed expire, then a sweep marks it
-- RETIRED. Both ACTIVE and ROTATING public keys are published in the JWKS.
CREATE TABLE mxid_oidc_keyset (
    id          BIGINT PRIMARY KEY,
    -- Opaque key id published as the JWK `kid`; clients select the verifying
    -- key by this during rotation overlaps.
    kid         VARCHAR(64)  NOT NULL UNIQUE,
    algorithm   VARCHAR(16)  NOT NULL DEFAULT 'RS256',
    -- PKIX "PUBLIC KEY" PEM. Public material only — safe at rest.
    public_key  TEXT         NOT NULL,
    -- PKCS#1 "RSA PRIVATE KEY" PEM, encrypted with the KEK (envelope crypto,
    -- pkg/crypto MasterKey). Never stored in plaintext.
    private_key TEXT         NOT NULL,
    -- 1 = active (signs), 2 = rotating (verify-only, still in JWKS),
    -- 3 = retired (dropped from JWKS).
    status      SMALLINT     NOT NULL DEFAULT 1,
    not_before  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Hot path: "give me the active signing key" and "list active+rotating for JWKS".
CREATE INDEX idx_oidc_keyset_status ON mxid_oidc_keyset (status);
