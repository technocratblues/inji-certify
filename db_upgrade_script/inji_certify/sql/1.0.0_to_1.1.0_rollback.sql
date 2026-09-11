-- NOTE: This upgrade intentionally allows cryptographic_binding_methods_supported and
-- proof_types_supported to be NULL, and downstream code treats NULL as "attribute is
-- absent from the credential-issuer metadata" -- which is NOT the same value as an empty
-- array/object. Coercing existing NULLs to ARRAY[]::TEXT[] / '{}'::jsonb here would silently
-- change published metadata semantics for any config that intentionally omits these fields.
--
-- This rollback therefore does NOT auto-backfill and does NOT restore the NOT NULL
-- constraint automatically. Restoring NOT NULL requires reverting to application code that
-- no longer relies on the "absent" semantics, plus a manual, reviewed decision on what value
-- (if any) each existing NULL row should take. Run the two SELECTs below first to see if any
-- rollback-blocking rows exist before proceeding manually.

SELECT config_id FROM certify.credential_config WHERE cryptographic_binding_methods_supported IS NULL;
SELECT config_id FROM certify.credential_config WHERE proof_types_supported IS NULL;

-- Once reviewed and only if you are certain no config relies on the "absent" semantics,
-- uncomment and run manually:
UPDATE certify.credential_config SET cryptographic_binding_methods_supported = ARRAY[]::TEXT[] WHERE cryptographic_binding_methods_supported IS NULL;
UPDATE certify.credential_config SET proof_types_supported = '{}'::jsonb WHERE proof_types_supported IS NULL;
ALTER TABLE certify.credential_config ALTER COLUMN cryptographic_binding_methods_supported SET NOT NULL;
ALTER TABLE certify.credential_config ALTER COLUMN proof_types_supported SET NOT NULL;