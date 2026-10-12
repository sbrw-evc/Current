-- +goose Up

-- Service accounts: machine identities with a role (docs/integrations.md §1).
CREATE TABLE service_accounts (
    id          bigserial PRIMARY KEY,
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    role_id     bigint NOT NULL REFERENCES roles (id),
    disabled    boolean NOT NULL DEFAULT false,
    created_by  text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX service_accounts_name_key ON service_accounts (lower(name));

-- API tokens "flow_…". Only HMAC-SHA256(keys#tokens in OpenBao, token) is
-- stored; the plaintext is shown once at creation.
CREATE TABLE api_tokens (
    id                 bigserial PRIMARY KEY,
    service_account_id bigint NOT NULL REFERENCES service_accounts (id) ON DELETE CASCADE,
    name               text NOT NULL,
    token_hash         text NOT NULL UNIQUE,
    display            text NOT NULL DEFAULT '', -- "flow_AbCd…"
    expires_at         timestamptz,
    last_used_at       timestamptz,
    last_used_from     text NOT NULL DEFAULT '',
    created_by         text NOT NULL DEFAULT '',
    created_at         timestamptz NOT NULL DEFAULT now(),
    revoked_at         timestamptz,
    revoked_by         text NOT NULL DEFAULT ''
);
CREATE INDEX api_tokens_account_idx ON api_tokens (service_account_id);

-- Microsoft Entra ID users.
ALTER TABLE users DROP CONSTRAINT users_source_check;
ALTER TABLE users ADD CONSTRAINT users_source_check CHECK (source IN ('local', 'ldap', 'entra'));

-- +goose Down
DELETE FROM users WHERE source = 'entra';
ALTER TABLE users DROP CONSTRAINT users_source_check;
ALTER TABLE users ADD CONSTRAINT users_source_check CHECK (source IN ('local', 'ldap'));
DROP TABLE api_tokens;
DROP TABLE service_accounts;
