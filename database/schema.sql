-- ── users ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user'
                          CHECK (role IN ('user', 'admin')),
    is_active     INTEGER NOT NULL DEFAULT 1,        -- 1 = actif, 0 = suspendu
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── quotas ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS quotas (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL UNIQUE,
    quota_max  INTEGER NOT NULL DEFAULT 104857600    -- 100 MB
                       CHECK (quota_max > 0),
    quota_used INTEGER NOT NULL DEFAULT 0
                       CHECK (quota_used >= 0),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ── files ─────────────────────────────────────────────────────────────────────
-- stored_name  : nom aléatoire du fichier chiffré sur disque (ex: a3f9b2.enc)
-- sha256_hash  : empreinte du fichier ORIGINAL pour vérifier l'intégrité
-- signature    : signature RSA du fichier (prouve que c'est bien l'owner qui l'a uploadé)
CREATE TABLE IF NOT EXISTS files (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id      INTEGER NOT NULL,
    original_name TEXT    NOT NULL,
    stored_name   TEXT    NOT NULL UNIQUE,
    file_size     INTEGER NOT NULL CHECK (file_size > 0),
    sha256_hash   TEXT    NOT NULL,
    signature     TEXT    NOT NULL,                  -- signature RSA en base64
    uploaded_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ── shared_files ──────────────────────────────────────────────────────────────
-- On ne peut pas partager un fichier à soi-même.
-- On ne peut pas partager le même fichier deux fois au même destinataire.
CREATE TABLE IF NOT EXISTS shared_files (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id     INTEGER NOT NULL,
    shared_by   INTEGER NOT NULL,
    shared_with INTEGER NOT NULL,
    shared_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    CHECK (shared_by != shared_with),
    UNIQUE (file_id, shared_with),
    FOREIGN KEY (file_id)     REFERENCES files(id) ON DELETE CASCADE,
    FOREIGN KEY (shared_by)   REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (shared_with) REFERENCES users(id) ON DELETE CASCADE
);

-- ── logs ──────────────────────────────────────────────────────────────────────
-- action : 'login', 'logout', 'upload', 'download', 'delete', 'share', 'register'
CREATE TABLE IF NOT EXISTS logs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER,
    action    TEXT NOT NULL
              CHECK (action IN ('login','logout','upload','download','delete','share','register')),
    details   TEXT,
    ip        TEXT,                                  -- adresse IP de l'action
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
