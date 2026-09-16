-- AIOS v0.1 optional migration: trusted local time assessment
-- See docs/89-v0.1-trusted-time-expiry-and-randomness-semantics.md
-- This records time-confidence evidence only; it is not a network time service.

PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS time_trust_state (
    singleton_id                 INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    state                        TEXT NOT NULL CHECK (state IN ('TRUSTED_LOCAL', 'TIME_UNCERTAIN')),
    observed_wall_time           TEXT NOT NULL,
    last_trusted_wall_time       TEXT,
    rollback_tolerance_seconds   INTEGER NOT NULL CHECK (rollback_tolerance_seconds >= 0),
    source_class                 TEXT NOT NULL CHECK (source_class IN (
        'SYSTEM_RTC', 'SYSTEM_SYNCHRONIZED', 'ADMIN_CONFIRMED', 'TRUSTED_SERVICE', 'UNKNOWN'
    )),
    boot_id                      TEXT,
    reason_codes_json            TEXT NOT NULL,
    assessed_at                  TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_migrations(migration_id, checksum, applied_at)
VALUES ('0002_v0_1_time_trust', 'UNGENERATED-DRAFT-CHECKSUM', '2026-09-15T00:00:00Z');

COMMIT;
