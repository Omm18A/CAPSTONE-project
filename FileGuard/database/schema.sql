-- FileGuard schema. This file is the single source of truth: CMake embeds it
-- into the binary at configure time (see src/database/SchemaSql.h.in).
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT    NOT NULL UNIQUE,
  password_hash TEXT    NOT NULL,            -- hex PBKDF2-HMAC-SHA256 output
  salt          TEXT    NOT NULL,            -- hex, 16 random bytes per user
  iterations    INTEGER NOT NULL,            -- PBKDF2 cost used for this user
  role          TEXT    NOT NULL CHECK (role IN ('OWNER','USER','ADMIN')),
  created_at    TEXT    NOT NULL,
  status        TEXT    NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','DISABLED'))
);

CREATE TABLE IF NOT EXISTS files (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  file_uuid      TEXT    NOT NULL UNIQUE,    -- FG-10001
  owner_id       INTEGER NOT NULL REFERENCES users(id),
  original_name  TEXT    NOT NULL,
  protected_path TEXT    NOT NULL,
  original_size  INTEGER NOT NULL,
  original_hash  TEXT    NOT NULL,           -- SHA-256 (hex) of the plaintext
  protected_hash TEXT    NOT NULL,           -- SHA-256 (hex) of the .fguard file
  wrapped_key    BLOB    NOT NULL,           -- per-file key, AES-256-GCM wrapped by master key
  created_at     TEXT    NOT NULL,
  status         TEXT    NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','DISABLED'))
);

CREATE TABLE IF NOT EXISTS permissions (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id    INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  permission TEXT    NOT NULL CHECK (permission IN ('VIEW','READ','DOWNLOAD')),
  granted_by INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT    NOT NULL,
  expires_at TEXT,                           -- NULL = never; UTC 'YYYY-MM-DD HH:MM:SS'
  UNIQUE (file_id, user_id)
);

CREATE TABLE IF NOT EXISTS access_logs (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id   INTEGER REFERENCES files(id),
  user_id   INTEGER REFERENCES users(id),
  action    TEXT NOT NULL,
  result    TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  details   TEXT
);

CREATE TABLE IF NOT EXISTS security_events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id    INTEGER REFERENCES files(id),
  user_id    INTEGER REFERENCES users(id),
  event_type TEXT NOT NULL,
  severity   TEXT NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH')),
  timestamp  TEXT NOT NULL,
  details    TEXT
);

CREATE TABLE IF NOT EXISTS login_attempts (   -- failed logins, for lockout
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT    NOT NULL,
  ts       INTEGER NOT NULL                    -- epoch seconds
);

CREATE INDEX IF NOT EXISTS idx_access_logs_file ON access_logs(file_id);
CREATE INDEX IF NOT EXISTS idx_access_logs_user ON access_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_security_file    ON security_events(file_id);
CREATE INDEX IF NOT EXISTS idx_login_attempts   ON login_attempts(username, ts);
