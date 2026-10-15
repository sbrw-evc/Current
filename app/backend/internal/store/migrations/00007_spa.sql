-- +goose Up

-- Sign-in and access move to SPA, the Single Point of Authorization
-- (docs/identity-federation.md): Flow keeps no passwords, no password policy,
-- no passkeys and no directory or provider settings any more.

DROP TABLE passkeys;
DROP TABLE group_roles;

-- Users keep their IDs (saved views, tokens, audit). Every existing account
-- becomes "legacy": it is bound to its SPA person on the first SPA sign-in or
-- synchronization by the user name (once; afterwards by sub only), and a
-- legacy account no SPA person claims is disabled by the first successful
-- synchronization.
DROP INDEX users_external_key;
ALTER TABLE users DROP CONSTRAINT users_source_check;
UPDATE users SET source = 'legacy', external_id = '';
ALTER TABLE users ADD CONSTRAINT users_source_check CHECK (source IN ('legacy', 'spa'));
ALTER TABLE users ADD CONSTRAINT users_spa_bound CHECK (source <> 'spa' OR external_id <> '');
ALTER TABLE users ALTER COLUMN source SET DEFAULT 'spa';
ALTER TABLE users DROP COLUMN password_ref;
ALTER TABLE users DROP COLUMN password_changed_at;
CREATE UNIQUE INDEX users_spa_key ON users (external_id) WHERE source = 'spa';

-- The stable identifier of a role: what Flow publishes to SPA as its role
-- catalogue and what the "roles" claim of SPA names.
ALTER TABLE roles ADD COLUMN ident text;
UPDATE roles SET ident = 'admin' WHERE builtin AND lower(name) = 'administrator';
UPDATE roles SET ident = 'viewer' WHERE builtin AND lower(name) = 'viewer';
UPDATE roles r SET ident = s.slug
    FROM (SELECT id, slug, row_number() OVER (PARTITION BY slug ORDER BY id) AS n
          FROM (SELECT id, left(trim(both '-' from lower(regexp_replace(name, '[^A-Za-z0-9_.:]+', '-', 'g'))), 56) AS slug
                FROM roles WHERE ident IS NULL) x) s
    WHERE r.id = s.id AND s.n = 1 AND s.slug <> '' AND s.slug NOT IN ('admin', 'viewer');
UPDATE roles SET ident = 'role-' || id WHERE ident IS NULL;
ALTER TABLE roles ALTER COLUMN ident SET NOT NULL;
CREATE UNIQUE INDEX roles_ident_key ON roles (ident);

-- An API token belongs to the person who created it: it stops working while
-- SPA keeps that person disabled.
ALTER TABLE api_tokens ADD COLUMN created_by_id bigint REFERENCES users (id) ON DELETE SET NULL;
UPDATE api_tokens t SET created_by_id = u.id FROM users u WHERE lower(u.username) = lower(t.created_by);

DELETE FROM settings WHERE key IN ('password_policy', 'ldap', 'entra', 'providers', 'passkeys', 'umbrella_identity');

-- +goose Down
ALTER TABLE api_tokens DROP COLUMN created_by_id;
DROP INDEX roles_ident_key;
ALTER TABLE roles DROP COLUMN ident;
DROP INDEX users_spa_key;
ALTER TABLE users ADD COLUMN password_changed_at timestamptz;
ALTER TABLE users ADD COLUMN password_ref text NOT NULL DEFAULT '';
ALTER TABLE users ALTER COLUMN source SET DEFAULT 'local';
ALTER TABLE users DROP CONSTRAINT users_spa_bound;
ALTER TABLE users DROP CONSTRAINT users_source_check;
-- SPA accounts become local accounts without a password.
UPDATE users SET source = 'local', external_id = '';
ALTER TABLE users ADD CONSTRAINT users_source_check
    CHECK (source IN ('local', 'ldap', 'entra', 'google', 'apple', 'oidc', 'umbrella'));
CREATE UNIQUE INDEX users_external_key ON users (source, external_id) WHERE external_id <> '';
CREATE TABLE group_roles (
    group_dn text PRIMARY KEY,
    role_id  bigint NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    position integer NOT NULL DEFAULT 0
);
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
