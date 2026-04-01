-- 001_initial.sql — Foundation schema for Shield.
--
-- Tables: users, sessions, audit_log, tickets, ticket_comments,
--         metrics, policies, integration_state.

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,
    role            TEXT    NOT NULL DEFAULT 'client'
                            CHECK (role IN ('admin','operator','support','client')),
    email           TEXT,
    totp_secret     TEXT,
    totp_enabled    INTEGER NOT NULL DEFAULT 0,
    security_label  TEXT    NOT NULL DEFAULT 'internal'
                            CHECK (security_label IN ('public','internal','confidential','restricted')),
    attributes      TEXT    NOT NULL DEFAULT '{}',   -- JSON: arbitrary ABAC attributes
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    last_login_at   TEXT,
    is_active       INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT    PRIMARY KEY,              -- UUID v4
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      TEXT    NOT NULL,                 -- SHA-256 of session token
    ip_address      TEXT,
    user_agent      TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at      TEXT    NOT NULL,
    is_revoked      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sessions_user   ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER REFERENCES users(id),
    action          TEXT    NOT NULL,
    resource_type   TEXT,
    resource_id     TEXT,
    details         TEXT,                             -- JSON
    ip_address      TEXT,
    policy_chain    TEXT,                             -- JSON: full reasoning chain from policy engine
    outcome         TEXT    NOT NULL DEFAULT 'success'
                            CHECK (outcome IN ('success','denied','error')),
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_user    ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action  ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);

CREATE TABLE IF NOT EXISTS tickets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    title           TEXT    NOT NULL,
    description     TEXT    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'open'
                            CHECK (status IN ('open','in_progress','resolved','closed')),
    priority        TEXT    NOT NULL DEFAULT 'medium'
                            CHECK (priority IN ('low','medium','high','critical')),
    category        TEXT    NOT NULL DEFAULT 'general',
    created_by      INTEGER NOT NULL REFERENCES users(id),
    assigned_to     INTEGER REFERENCES users(id),
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    resolved_at     TEXT,
    closed_at       TEXT
);

CREATE INDEX IF NOT EXISTS idx_tickets_status  ON tickets(status);
CREATE INDEX IF NOT EXISTS idx_tickets_creator ON tickets(created_by);

CREATE TABLE IF NOT EXISTS ticket_comments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id       INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    user_id         INTEGER NOT NULL REFERENCES users(id),
    body            TEXT    NOT NULL,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_comments_ticket ON ticket_comments(ticket_id);

CREATE TABLE IF NOT EXISTS metrics (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    metric_type     TEXT    NOT NULL,                 -- e.g. "cpu", "memory", "disk", "network"
    metric_name     TEXT    NOT NULL,                 -- e.g. "usage_percent", "bytes_sent"
    value           REAL    NOT NULL,
    labels          TEXT,                             -- JSON key-value pairs
    recorded_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_metrics_type ON metrics(metric_type, recorded_at);

CREATE TABLE IF NOT EXISTS policies (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    layer           TEXT    NOT NULL
                            CHECK (layer IN ('rbac','abac','pbac','mac','sod','contextual')),
    definition      TEXT    NOT NULL,                 -- JSON policy body
    is_active       INTEGER NOT NULL DEFAULT 1,
    priority        INTEGER NOT NULL DEFAULT 0,       -- higher = evaluated first
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS integration_state (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    integration_name    TEXT    NOT NULL UNIQUE,
    last_sync_at        TEXT,
    status              TEXT    NOT NULL DEFAULT 'unknown'
                                CHECK (status IN ('unknown','healthy','degraded','error')),
    error_message       TEXT,
    metadata            TEXT,                         -- JSON
    updated_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Seed the default admin user (password: changeme, argon2 hash generated at first boot).
-- The application handles first-boot seeding, not SQL.
