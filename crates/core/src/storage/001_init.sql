-- Connection inventory. Secrets are never stored here: `secret_ref` is an opaque
-- id into the CredentialStore (OS keyring or encrypted vault).

CREATE TABLE groups (
    id        TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    sort      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE profiles (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    host           TEXT NOT NULL,
    port           INTEGER CHECK (port BETWEEN 1 AND 65535),
    username       TEXT,
    group_id       TEXT REFERENCES groups(id) ON DELETE SET NULL,
    auth           TEXT NOT NULL DEFAULT 'auto' CHECK (auth IN ('auto', 'password', 'key', 'agent')),
    identity_file  TEXT,
    jump           TEXT,
    start_dir      TEXT,
    keepalive_secs INTEGER CHECK (keepalive_secs BETWEEN 0 AND 3600),
    terminal_theme TEXT,
    color          TEXT,
    icon           TEXT,
    favorite       INTEGER NOT NULL DEFAULT 0,
    legacy_crypto  INTEGER NOT NULL DEFAULT 0,
    secret_ref     TEXT,
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL,
    last_used_at   INTEGER
);

CREATE TABLE profile_tags (
    profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    tag        TEXT NOT NULL,
    PRIMARY KEY (profile_id, tag)
);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL -- JSON
);
