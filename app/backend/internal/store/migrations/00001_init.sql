-- +goose Up

CREATE TABLE roles (
    id          bigserial PRIMARY KEY,
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    builtin     boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX roles_name_key ON roles (lower(name));

CREATE TABLE role_permissions (
    role_id    bigint NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission text NOT NULL,
    PRIMARY KEY (role_id, permission)
);

CREATE TABLE users (
    id            bigserial PRIMARY KEY,
    username      text NOT NULL,
    name          text NOT NULL DEFAULT '',
    email         text NOT NULL DEFAULT '',
    source        text NOT NULL DEFAULT 'local' CHECK (source IN ('local', 'ldap')),
    -- openbao://<mount>/users/<id>#password_hash: the PBKDF2-SHA256 hash lives in OpenBao;
    -- empty for directory users.
    password_ref  text NOT NULL DEFAULT '',
    role_id       bigint NOT NULL REFERENCES roles (id),
    disabled      boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz
);
CREATE UNIQUE INDEX users_username_key ON users (lower(username));

CREATE TABLE sessions (
    -- HMAC-SHA256 of the cookie value with a key kept in OpenBao: a database dump
    -- gives neither working sessions nor CSRF tokens (those are derived from the key too).
    id_hash    text PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    remote     text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sessions_user_idx ON sessions (user_id);

-- Directory group (normalized DN) -> role. The first matching row by position wins.
CREATE TABLE group_roles (
    group_dn text PRIMARY KEY,
    role_id  bigint NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    position integer NOT NULL DEFAULT 0
);

CREATE TABLE settings (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE saved_views (
    id         bigserial PRIMARY KEY,
    name       text NOT NULL,
    owner_id   bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    shared     boolean NOT NULL DEFAULT false,
    request    jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX saved_views_owner_idx ON saved_views (owner_id);

-- Ordered CEL rules per kind (exporter, interface).
CREATE TABLE classifiers (
    kind       text NOT NULL,
    position   integer NOT NULL,
    rule       text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, position)
);

-- Secrets are never stored here: every *_ref column holds an openbao:// reference.

-- Single row: the Inventory DB connection.
CREATE TABLE inventory_db (
    id               integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled          boolean NOT NULL DEFAULT false,
    url              text NOT NULL DEFAULT '',
    token_ref        text NOT NULL DEFAULT '',
    interval_seconds integer NOT NULL DEFAULT 900 CHECK (interval_seconds >= 60),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    last_sync_at     timestamptz,
    last_sync_ok     boolean,
    last_sync_error  text NOT NULL DEFAULT '',
    last_sync_stats  jsonb NOT NULL DEFAULT '{}'
);
INSERT INTO inventory_db (id) VALUES (1);

-- Sampling rate overrides: exporter address or network, interface ifIndex (0 = all interfaces).
CREATE TABLE sampling_overrides (
    exporter   cidr NOT NULL,
    if_index   bigint NOT NULL DEFAULT 0 CHECK (if_index >= 0),
    rate       bigint NOT NULL CHECK (rate > 0),
    comment    text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (exporter, if_index)
);

CREATE TABLE audit_log (
    id     bigserial PRIMARY KEY,
    at     timestamptz NOT NULL DEFAULT now(),
    actor  text NOT NULL DEFAULT '',
    action text NOT NULL,
    target text NOT NULL DEFAULT '',
    remote text NOT NULL DEFAULT '',
    detail jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_log_at_idx ON audit_log (at DESC);

-- +goose Down
DROP TABLE audit_log;
DROP TABLE sampling_overrides;
DROP TABLE inventory_db;
DROP TABLE classifiers;
DROP TABLE saved_views;
DROP TABLE settings;
DROP TABLE group_roles;
DROP TABLE sessions;
DROP TABLE users;
DROP TABLE role_permissions;
DROP TABLE roles;
