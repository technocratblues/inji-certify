-- Make cryptographic_binding_methods_supported and proof_types_supported nullable
-- on credential_config, since these values are now optionally derived/overridable
-- and should not be mandatory at insert time.

ALTER TABLE certify.credential_config
    ALTER COLUMN cryptographic_binding_methods_supported DROP NOT NULL;

ALTER TABLE certify.credential_config
    ALTER COLUMN proof_types_supported DROP NOT NULL;