-- Exact definitions shipped under the 0013 stamp at PR head 5eb3b71.
-- These are the only changed-but-present provider triggers eligible for
-- fenced replacement when opening a stamped historical database.
CREATE TRIGGER IF NOT EXISTS execution_binding_trust_marker_insert
BEFORE INSERT ON execution_bindings
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM provider_registrations r
        WHERE r.registration_id=NEW.provider_registration_id
          AND r.state<>'revoked'
          AND r.trust_status NOT IN ('denied','revoked')
          AND (r.trust_status IN ('locally-trusted','project-reviewed','organization-approved')
               OR EXISTS (SELECT 1 FROM provider_trust_admissions a
                          WHERE a.registration_id=r.registration_id))
    ) THEN RAISE(ABORT, 'binding requires current trusted provider admission') END;
    INSERT INTO execution_binding_trust_markers(binding_id,trust_source_id)
    SELECT NEW.binding_id, COALESCE(
        (SELECT a.admission_id FROM provider_trust_admissions a
         WHERE a.registration_id=NEW.provider_registration_id
         ORDER BY a.revision DESC LIMIT 1),
        NEW.provider_registration_id
    );
END;

CREATE TRIGGER IF NOT EXISTS execution_binding_trust_not_future
BEFORE INSERT ON execution_bindings
WHEN NOT EXISTS (
    WITH latest AS (
        SELECT COALESCE(
            (SELECT admitted_at FROM provider_trust_admissions
             WHERE registration_id=NEW.provider_registration_id
             ORDER BY revision DESC LIMIT 1),
            (SELECT registered_at FROM provider_registrations
             WHERE registration_id=NEW.provider_registration_id)
        ) AS admitted_at
    ), times AS (
        SELECT CAST(strftime('%s', admitted_at) AS INTEGER) AS admitted_second,
               CAST(strftime('%s', NEW.created_at) AS INTEGER) AS created_second,
               substr(CASE WHEN substr(admitted_at,20,1)='.' THEN
                   substr(admitted_at,21,
                       instr(replace(replace(replace(substr(admitted_at,21),'+','Z'),'-','Z'),'z','Z'),'Z')-1)
                   ELSE '' END || '000000000',1,9) AS admitted_fraction,
               substr(CASE WHEN substr(NEW.created_at,20,1)='.' THEN
                   substr(NEW.created_at,21,
                       instr(replace(replace(replace(substr(NEW.created_at,21),'+','Z'),'-','Z'),'z','Z'),'Z')-1)
                   ELSE '' END || '000000000',1,9) AS created_fraction
        FROM latest
    )
    SELECT 1 FROM times
    WHERE admitted_second IS NOT NULL AND created_second IS NOT NULL
      AND (admitted_second < created_second OR
           (admitted_second=created_second AND admitted_fraction<=created_fraction))
)
BEGIN SELECT RAISE(ABORT, 'binding predates provider trust admission'); END;
