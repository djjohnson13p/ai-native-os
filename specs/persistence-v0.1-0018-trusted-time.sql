-- Reconciled Stage-1 trusted-time anchor. The optional 0002 time-trust draft is not executed.
-- Nanoseconds are bounded to SQLite INTEGER by the trusted-core parser before insertion.
CREATE TABLE IF NOT EXISTS trusted_time_state (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id=1),
    confidence TEXT NOT NULL CHECK (confidence IN ('UNASSESSED','TRUSTED_LOCAL','TIME_UNCERTAIN')),
    high_water_unix_nanos INTEGER,
    expiry_floor_unix_nanos INTEGER,
    reason_code TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision>=0),
    CHECK ((confidence='UNASSESSED' AND high_water_unix_nanos IS NULL
            AND expiry_floor_unix_nanos IS NULL AND revision=0)
        OR (confidence='TRUSTED_LOCAL' AND revision>0
            AND high_water_unix_nanos IS NOT NULL
            AND expiry_floor_unix_nanos>=high_water_unix_nanos)
        OR (confidence='TIME_UNCERTAIN' AND revision>0
            AND (high_water_unix_nanos IS NULL OR expiry_floor_unix_nanos>=high_water_unix_nanos)))
);
INSERT INTO trusted_time_state(singleton_id,confidence,high_water_unix_nanos,
    expiry_floor_unix_nanos,reason_code,revision)
SELECT 1,'UNASSESSED',NULL,NULL,'TIME_UNASSESSED',0
WHERE NOT EXISTS (SELECT 1 FROM trusted_time_state WHERE singleton_id=1);
CREATE TABLE IF NOT EXISTS trusted_time_observations (
    observation_id INTEGER PRIMARY KEY,
    state_revision INTEGER NOT NULL UNIQUE,
    observed_unix_nanos INTEGER,
    monotonic_nanos INTEGER,
    high_water_unix_nanos INTEGER,
    expiry_floor_unix_nanos INTEGER,
    confidence TEXT NOT NULL CHECK (confidence IN ('TRUSTED_LOCAL','TIME_UNCERTAIN')),
    reason_code TEXT NOT NULL,
    source_class TEXT NOT NULL CHECK (source_class IN ('SYSTEM_CLOCK','INJECTED_CLOCK','UNAVAILABLE'))
);
CREATE TRIGGER IF NOT EXISTS trusted_time_state_no_duplicate
BEFORE INSERT ON trusted_time_state
WHEN EXISTS (SELECT 1 FROM trusted_time_state WHERE singleton_id=NEW.singleton_id)
BEGIN SELECT RAISE(ABORT,'trusted time state already exists'); END;
CREATE TRIGGER IF NOT EXISTS trusted_time_state_monotone
BEFORE UPDATE ON trusted_time_state
WHEN NEW.singleton_id<>OLD.singleton_id OR NEW.revision<>OLD.revision+1
  OR (OLD.high_water_unix_nanos IS NOT NULL AND
      (NEW.high_water_unix_nanos IS NULL OR NEW.high_water_unix_nanos<OLD.high_water_unix_nanos))
  OR (OLD.expiry_floor_unix_nanos IS NOT NULL AND
      (NEW.expiry_floor_unix_nanos IS NULL OR NEW.expiry_floor_unix_nanos<OLD.expiry_floor_unix_nanos))
  OR (OLD.confidence='TIME_UNCERTAIN' AND NEW.confidence<>'TIME_UNCERTAIN')
BEGIN SELECT RAISE(ABORT,'trusted time cannot move backward or auto-clear'); END;
CREATE TRIGGER IF NOT EXISTS trusted_time_state_no_delete
BEFORE DELETE ON trusted_time_state
BEGIN SELECT RAISE(ABORT,'trusted time state is durable'); END;
CREATE TRIGGER IF NOT EXISTS trusted_time_observation_no_duplicate
BEFORE INSERT ON trusted_time_observations
WHEN EXISTS (SELECT 1 FROM trusted_time_observations
             WHERE observation_id=NEW.observation_id OR state_revision=NEW.state_revision)
BEGIN SELECT RAISE(ABORT,'trusted time observation already exists'); END;
CREATE TRIGGER IF NOT EXISTS trusted_time_observation_no_update
BEFORE UPDATE ON trusted_time_observations
BEGIN SELECT RAISE(ABORT,'trusted time observation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS trusted_time_observation_no_delete
BEFORE DELETE ON trusted_time_observations
BEGIN SELECT RAISE(ABORT,'trusted time observation is durable'); END;
