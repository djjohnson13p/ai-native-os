CREATE TRIGGER IF NOT EXISTS execution_binding_evidence_present_at_insert
BEFORE INSERT ON execution_bindings
WHEN aios_binding_evidence_pin_v1(NEW.binding_json) IS NOT NULL
 AND NOT EXISTS (
    SELECT 1 FROM provider_conformance_evidence e
    WHERE e.evidence_id=aios_binding_evidence_pin_v1(NEW.binding_json)
      AND e.registration_id=NEW.provider_registration_id
      AND e.capability=NEW.capability
      AND e.contract_hash=NEW.capability_contract_hash
      AND e.status='pass'
      AND e.suite_id IS NOT NULL AND e.suite_hash IS NOT NULL
      AND EXISTS (
          SELECT 1 FROM provider_manifest_payloads m,
               json_each(m.manifest_json,'$.provides') AS offered
          WHERE m.registration_id=NEW.provider_registration_id
            AND json_valid(m.manifest_json)
            AND json_extract(offered.value,'$.contract.capability') IS
                substr(NEW.capability,1,instr(NEW.capability,'@')-1)
            AND json_extract(offered.value,'$.contract.contract_hash') IS NEW.capability_contract_hash
            AND json_extract(offered.value,'$.conformance.suite') IS e.suite_id
            AND json_extract(offered.value,'$.conformance.suite_hash') IS e.suite_hash
      )
)
BEGIN SELECT RAISE(ABORT, 'binding conformance evidence was not admitted'); END;

CREATE TRIGGER IF NOT EXISTS execution_binding_evidence_not_future
BEFORE INSERT ON execution_bindings
WHEN NOT EXISTS (
    WITH pin AS (
        SELECT tested_at FROM provider_conformance_evidence
        WHERE evidence_id=aios_binding_evidence_pin_v1(NEW.binding_json)
    ), times AS (
        SELECT
            COALESCE(CAST(strftime('%s', tested_at) AS INTEGER),CASE WHEN substr(tested_at,-6,1) IN ('+','-') AND substr(tested_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(tested_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(tested_at,1,length(tested_at)-6)||'Z') AS INTEGER) - (CASE substr(tested_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(tested_at,-5,2) AS INTEGER)*3600 + CAST(substr(tested_at,-2,2) AS INTEGER)*60) END) AS tested_second,
            COALESCE(CAST(strftime('%s', NEW.created_at) AS INTEGER),CASE WHEN substr(NEW.created_at,-6,1) IN ('+','-') AND substr(NEW.created_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(NEW.created_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(NEW.created_at,1,length(NEW.created_at)-6)||'Z') AS INTEGER) - (CASE substr(NEW.created_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(NEW.created_at,-5,2) AS INTEGER)*3600 + CAST(substr(NEW.created_at,-2,2) AS INTEGER)*60) END) AS created_second,
            substr(CASE WHEN substr(tested_at,20,1)='.' THEN
                substr(tested_at,21,
                    instr(replace(replace(replace(substr(tested_at,21),'+','Z'),'-','Z'),'z','Z'),'Z')-1)
                ELSE '' END || '000000000',1,9) AS tested_fraction,
            substr(CASE WHEN substr(NEW.created_at,20,1)='.' THEN
                substr(NEW.created_at,21,
                    instr(replace(replace(replace(substr(NEW.created_at,21),'+','Z'),'-','Z'),'z','Z'),'Z')-1)
                ELSE '' END || '000000000',1,9) AS created_fraction
        FROM pin
    )
    SELECT 1 FROM times
    WHERE tested_second IS NOT NULL AND created_second IS NOT NULL
      AND (tested_second < created_second OR
           (tested_second = created_second AND tested_fraction <= created_fraction))
)
BEGIN SELECT RAISE(ABORT, 'binding predates pinned conformance evidence'); END;

CREATE TRIGGER IF NOT EXISTS execution_binding_evidence_unexpired_at_insert
BEFORE INSERT ON execution_bindings
WHEN NOT EXISTS (
    WITH pin AS (
        SELECT evidence_json FROM provider_conformance_evidence
        WHERE evidence_id=aios_binding_evidence_pin_v1(NEW.binding_json)
    ), expiry AS (
        SELECT json_extract(evidence_json, '$.expires_at') AS expires_at,
               json_type(evidence_json, '$.expires_at') AS expiry_type
        FROM pin WHERE json_valid(evidence_json)
    ), times AS (
        SELECT expiry_type,
               COALESCE(CAST(strftime('%s', expires_at) AS INTEGER),CASE WHEN substr(expires_at,-6,1) IN ('+','-') AND substr(expires_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(expires_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(expires_at,1,length(expires_at)-6)||'Z') AS INTEGER) - (CASE substr(expires_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(expires_at,-5,2) AS INTEGER)*3600 + CAST(substr(expires_at,-2,2) AS INTEGER)*60) END) AS expiry_second,
               COALESCE(CAST(strftime('%s', NEW.created_at) AS INTEGER),CASE WHEN substr(NEW.created_at,-6,1) IN ('+','-') AND substr(NEW.created_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(NEW.created_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(NEW.created_at,1,length(NEW.created_at)-6)||'Z') AS INTEGER) - (CASE substr(NEW.created_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(NEW.created_at,-5,2) AS INTEGER)*3600 + CAST(substr(NEW.created_at,-2,2) AS INTEGER)*60) END) AS created_second,
               substr(CASE WHEN substr(expires_at,20,1)='.' THEN
                   substr(expires_at,21,
                       instr(replace(replace(replace(substr(expires_at,21),'+','Z'),'-','Z'),'z','Z'),'Z')-1)
                   ELSE '' END || '000000000',1,9) AS expiry_fraction,
               substr(CASE WHEN substr(NEW.created_at,20,1)='.' THEN
                   substr(NEW.created_at,21,
                       instr(replace(replace(replace(substr(NEW.created_at,21),'+','Z'),'-','Z'),'z','Z'),'Z')-1)
                   ELSE '' END || '000000000',1,9) AS created_fraction
        FROM expiry
    )
    SELECT 1 FROM times
    WHERE expiry_type IS NULL OR expiry_type='null'
       OR (expiry_type='text' AND expiry_second IS NOT NULL AND created_second IS NOT NULL
           AND (expiry_second>created_second OR
                (expiry_second=created_second AND expiry_fraction>created_fraction)))
)
BEGIN SELECT RAISE(ABORT, 'binding conformance evidence expired at creation'); END;

CREATE TRIGGER IF NOT EXISTS execution_binding_evidence_latest_at_insert
BEFORE INSERT ON execution_bindings
WHEN NOT EXISTS (
    WITH clock AS (
        SELECT COALESCE(CAST(strftime('%s', NEW.created_at) AS INTEGER),CASE WHEN substr(NEW.created_at,-6,1) IN ('+','-') AND substr(NEW.created_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(NEW.created_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(NEW.created_at,1,length(NEW.created_at)-6)||'Z') AS INTEGER) - (CASE substr(NEW.created_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(NEW.created_at,-5,2) AS INTEGER)*3600 + CAST(substr(NEW.created_at,-2,2) AS INTEGER)*60) END) AS second,
               substr(CASE WHEN substr(NEW.created_at,20,1)='.' THEN
                   substr(NEW.created_at,21,
                       instr(replace(replace(replace(substr(NEW.created_at,21),'+','Z'),'-','Z'),'z','Z'),'Z')-1)
                   ELSE '' END || '000000000',1,9) AS fraction
    ), pin AS (
        SELECT registration_id,capability,contract_hash,suite_id,suite_hash
        FROM provider_conformance_evidence
        WHERE evidence_id=aios_binding_evidence_pin_v1(NEW.binding_json)
          AND suite_id IS NOT NULL AND suite_hash IS NOT NULL
    ), candidates AS (
        SELECT e.evidence_id,e.status,
               COALESCE(CAST(strftime('%s', e.tested_at) AS INTEGER),CASE WHEN substr(e.tested_at,-6,1) IN ('+','-') AND substr(e.tested_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(e.tested_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(e.tested_at,1,length(e.tested_at)-6)||'Z') AS INTEGER) - (CASE substr(e.tested_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(e.tested_at,-5,2) AS INTEGER)*3600 + CAST(substr(e.tested_at,-2,2) AS INTEGER)*60) END) AS second,
               substr(CASE WHEN substr(e.tested_at,20,1)='.' THEN
                   substr(e.tested_at,21,
                       instr(replace(replace(replace(substr(e.tested_at,21),'+','Z'),'-','Z'),'z','Z'),'Z')-1)
                   ELSE '' END || '000000000',1,9) AS fraction
        FROM provider_conformance_evidence e JOIN pin p
          ON e.registration_id=p.registration_id AND e.capability=p.capability
         AND e.contract_hash=p.contract_hash AND e.suite_id=p.suite_id
         AND e.suite_hash=p.suite_hash
    ), eligible AS (
        SELECT c.* FROM candidates c, clock t
        WHERE c.second IS NOT NULL AND t.second IS NOT NULL
          AND (c.second<t.second OR
               (c.second=t.second AND c.fraction<=t.fraction))
    )
    SELECT 1 FROM eligible selected
    WHERE selected.evidence_id=aios_binding_evidence_pin_v1(NEW.binding_json)
      AND selected.status='pass'
      AND NOT EXISTS (SELECT 1 FROM candidates WHERE second IS NULL)
      AND NOT EXISTS (
          SELECT 1 FROM eligible other
          WHERE other.evidence_id<>selected.evidence_id
            AND (other.second>selected.second OR
                 (other.second=selected.second AND other.fraction>=selected.fraction))
      )
)
BEGIN SELECT RAISE(ABORT, 'binding conformance evidence is not latest'); END;
