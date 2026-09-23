CREATE TRIGGER IF NOT EXISTS provider_trust_admission_receipt_insert
BEFORE INSERT ON provider_trust_admissions
WHEN CASE WHEN json_valid(NEW.receipt_json) THEN
    json_extract(NEW.receipt_json,'$.registration_id') IS NOT NEW.registration_id
    OR json_extract(NEW.receipt_json,'$.decision_id') IS NOT NEW.decision_id
    OR json_extract(NEW.receipt_json,'$.revision') IS NOT NEW.revision
    OR json_extract(NEW.receipt_json,'$.trust_status') IS NOT NEW.trust_status
    OR json_extract(NEW.receipt_json,'$.authority_ref') IS NOT NEW.authority_ref
    OR json_extract(NEW.receipt_json,'$.admitted_at') IS NOT NEW.admitted_at
    OR NEW.revision IS NOT COALESCE((SELECT MAX(revision)+1
        FROM provider_trust_admissions WHERE registration_id=NEW.registration_id),1)
    ELSE 1 END
BEGIN SELECT RAISE(ABORT, 'provider trust admission receipt mismatch'); END;
