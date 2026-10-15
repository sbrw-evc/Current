-- +goose Up

-- Umbrella Identity (docs/identity-federation.md): accounts of Google, Apple,
-- OpenID Connect and of the Umbrella hub, bound by the provider's subject;
-- the time of the last password change (expiry); passkeys.
ALTER TABLE users DROP CONSTRAINT users_source_check;
ALTER TABLE users ADD CONSTRAINT users_source_check
    CHECK (source IN ('local', 'ldap', 'entra', 'google', 'apple', 'oidc', 'umbrella'));
ALTER TABLE users ADD COLUMN external_id text NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN password_changed_at timestamptz;
UPDATE users SET password_changed_at = updated_at WHERE source = 'local' AND password_ref <> '';
CREATE UNIQUE INDEX users_external_key ON users (source, external_id) WHERE external_id <> '';

-- Passkeys (WebAuthn): only public keys. hub_id is set for passkeys
-- synchronized from Umbrella Monitoring; they are replaced at every
-- synchronization.
CREATE TABLE passkeys (
    id              bigserial PRIMARY KEY,
    user_id         bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name            text NOT NULL DEFAULT '',
    credential_id   bytea NOT NULL,
    public_key      bytea NOT NULL,
    user_handle     bytea NOT NULL,
    sign_count      bigint NOT NULL DEFAULT 0,
    aaguid          bytea NOT NULL DEFAULT '\x'::bytea,
    transports      text[] NOT NULL DEFAULT '{}',
    backup_eligible boolean NOT NULL DEFAULT false,
    backup_state    boolean NOT NULL DEFAULT false,
    hub_id          text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz
);
CREATE UNIQUE INDEX passkeys_credential_key ON passkeys (credential_id);
CREATE INDEX passkeys_user_idx ON passkeys (user_id);

-- +goose Down
DROP TABLE passkeys;
DROP INDEX users_external_key;
ALTER TABLE users DROP COLUMN password_changed_at;
ALTER TABLE users DROP COLUMN external_id;
DELETE FROM users WHERE source IN ('google', 'apple', 'oidc', 'umbrella');
ALTER TABLE users DROP CONSTRAINT users_source_check;
ALTER TABLE users ADD CONSTRAINT users_source_check CHECK (source IN ('local', 'ldap', 'entra'));
