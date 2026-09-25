CREATE DATABASE inji_certify_mock
  ENCODING = 'UTF8'
  LC_COLLATE = 'en_US.UTF-8'
  LC_CTYPE = 'en_US.UTF-8'
  TABLESPACE = pg_default
  OWNER = postgres
  TEMPLATE  = template0;

COMMENT ON DATABASE inji_certify_mock IS 'isolated mock-mdl mdoc credential data is stored in this database';

\c inji_certify_mock postgres

DROP SCHEMA IF EXISTS certify CASCADE;
CREATE SCHEMA certify;
ALTER SCHEMA certify OWNER TO postgres;
ALTER DATABASE inji_certify_mock SET search_path TO certify,pg_catalog,public;

--- keymanager specific DB changes ---
CREATE TABLE certify.key_alias(
                                  id character varying(36) NOT NULL,
                                  app_id character varying(36) NOT NULL,
                                  ref_id character varying(128),
                                  key_gen_dtimes timestamp,
                                  key_expire_dtimes timestamp,
                                  status_code character varying(36),
                                  lang_code character varying(3),
                                  cr_by character varying(256) NOT NULL,
                                  cr_dtimes timestamp NOT NULL,
                                  upd_by character varying(256),
                                  upd_dtimes timestamp,
                                  is_deleted boolean DEFAULT FALSE,
                                  del_dtimes timestamp,
                                  cert_thumbprint character varying(100),
                                  uni_ident character varying(50),
                                  CONSTRAINT pk_keymals_id PRIMARY KEY (id),
                                  CONSTRAINT uni_ident_const UNIQUE (uni_ident)
);

CREATE TABLE certify.key_policy_def(
                                       app_id character varying(36) NOT NULL,
                                       key_validity_duration smallint,
                                       is_active boolean NOT NULL,
                                       pre_expire_days smallint,
                                       access_allowed character varying(1024),
                                       cr_by character varying(256) NOT NULL,
                                       cr_dtimes timestamp NOT NULL,
                                       upd_by character varying(256),
                                       upd_dtimes timestamp,
                                       is_deleted boolean DEFAULT FALSE,
                                       del_dtimes timestamp,
                                       CONSTRAINT pk_keypdef_id PRIMARY KEY (app_id)
);

CREATE TABLE certify.key_store(
                                  id character varying(36) NOT NULL,
                                  master_key character varying(36) NOT NULL,
                                  private_key character varying(2500) NOT NULL,
                                  certificate_data character varying NOT NULL,
                                  cr_by character varying(256) NOT NULL,
                                  cr_dtimes timestamp NOT NULL,
                                  upd_by character varying(256),
                                  upd_dtimes timestamp,
                                  is_deleted boolean DEFAULT FALSE,
                                  del_dtimes timestamp,
                                  CONSTRAINT pk_keystr_id PRIMARY KEY (id)
);

CREATE TABLE certify.ca_cert_store(
                                      cert_id character varying(36) NOT NULL,
                                      cert_subject character varying(500) NOT NULL,
                                      cert_issuer character varying(500) NOT NULL,
                                      issuer_id character varying(36) NOT NULL,
                                      cert_not_before timestamp,
                                      cert_not_after timestamp,
                                      crl_uri character varying(120),
                                      cert_data character varying,
                                      cert_thumbprint character varying(100),
                                      cert_serial_no character varying(50),
                                      partner_domain character varying(36),
                                      cr_by character varying(256),
                                      cr_dtimes timestamp,
                                      upd_by character varying(256),
                                      upd_dtimes timestamp,
                                      is_deleted boolean DEFAULT FALSE,
                                      del_dtimes timestamp,
                                      ca_cert_type character varying(25),
                                      CONSTRAINT pk_cacs_id PRIMARY KEY (cert_id),
                                      CONSTRAINT cert_thumbprint_unique UNIQUE (cert_thumbprint,partner_domain)

);

CREATE TABLE certify.rendering_template (
                                            id varchar(128) NOT NULL,
                                            template VARCHAR NOT NULL,
                                            cr_dtimes timestamp NOT NULL,
                                            upd_dtimes timestamp,
                                            CONSTRAINT pk_svgtmp_id PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS certify.credential_config (
                                                         credential_config_key_id VARCHAR(2048) NOT NULL UNIQUE,
    config_id VARCHAR(255) NOT NULL,
    status VARCHAR(255),
    vc_template VARCHAR,
    doctype VARCHAR,
    sd_jwt_vct VARCHAR,
    context VARCHAR,
    credential_type VARCHAR,
    credential_format VARCHAR(255) NOT NULL,
    did_url VARCHAR,
    key_manager_app_id VARCHAR(36),
    key_manager_ref_id VARCHAR(128),
    signature_algo VARCHAR(36),
    signature_crypto_suite VARCHAR(128),
    sd_claim VARCHAR,
    display JSONB NOT NULL,
    display_order TEXT[] NOT NULL,
    scope VARCHAR(255) NOT NULL,
    cryptographic_binding_methods_supported TEXT[],
    credential_signing_alg_values_supported TEXT[] NOT NULL,
    proof_types_supported JSONB,
    claims JSONB,
    sd_jwt_claims JSONB,
    mso_mdoc_claims JSONB,
    plugin_configurations JSONB,
    credential_status_purpose TEXT[],
    qr_settings JSONB,
    qr_signature_algo TEXT,
    cr_dtimes TIMESTAMP NOT NULL,
    upd_dtimes TIMESTAMP,
    CONSTRAINT pk_config_id PRIMARY KEY (config_id)
    );

CREATE UNIQUE INDEX idx_credential_config_type_context_unique
    ON certify.credential_config(credential_type, context, credential_format)
    WHERE credential_type IS NOT NULL AND credential_type <> ''
AND context IS NOT NULL AND context <> '';

CREATE UNIQUE INDEX idx_credential_config_sd_jwt_vct_unique
    ON certify.credential_config(sd_jwt_vct, credential_format)
    WHERE sd_jwt_vct IS NOT NULL and sd_jwt_vct <> '';

CREATE UNIQUE INDEX idx_credential_config_doctype_unique
    ON certify.credential_config(doctype, credential_format)
    WHERE doctype IS NOT NULL and doctype <> '';

-- DrivingLicenseCredential (mso_mdoc), backed by the CSV DataProvider plugin
-- (MockCSVDataProviderPlugin + driving_license_mosipid.csv), same pattern as FarmerCredential.
INSERT INTO certify.credential_config (
    credential_config_key_id,
    config_id,
    status,
    vc_template,
    doctype,
    sd_jwt_vct,
    context,
    credential_type,
    credential_format,
    did_url,
    key_manager_app_id,
    key_manager_ref_id,
    signature_algo,
    signature_crypto_suite,
    sd_claim,
    display,
    display_order,
    scope,
    cryptographic_binding_methods_supported,
    credential_signing_alg_values_supported,
    proof_types_supported,
    claims,
    mso_mdoc_claims,
    plugin_configurations,
    credential_status_purpose,
    qr_settings,
    qr_signature_algo,
    cr_dtimes,
    upd_dtimes
)
VALUES (
           'DrivingLicenseCredential',
           gen_random_uuid()::VARCHAR(255),  -- generating a unique config_id
           'active',  -- assuming an active status
           'ewogICJuYW1lU3BhY2VzIjogewogICAgIm9yZy5pc28uMTgwMTMuNS4xIjogWwogICAgICB7CiAgICAgICAgImRpZ2VzdElEIjogMCwKICAgICAgICAiZWxlbWVudElkZW50aWZpZXIiOiAiZmFtaWx5X25hbWUiLAogICAgICAgICJlbGVtZW50VmFsdWUiOiAiJHtmYW1pbHlOYW1lfSIKICAgICAgfSwKICAgICAgewogICAgICAgICJkaWdlc3RJRCI6IDEsCiAgICAgICAgImVsZW1lbnRJZGVudGlmaWVyIjogImdpdmVuX25hbWUiLAogICAgICAgICJlbGVtZW50VmFsdWUiOiAiJHtnaXZlbk5hbWV9IgogICAgICB9LAogICAgICB7CiAgICAgICAgImRpZ2VzdElEIjogMiwKICAgICAgICAiZWxlbWVudElkZW50aWZpZXIiOiAiYmlydGhfZGF0ZSIsCiAgICAgICAgImVsZW1lbnRWYWx1ZSI6ICIke2JpcnRoRGF0ZX0iCiAgICAgIH0sCiAgICAgIHsKICAgICAgICAiZGlnZXN0SUQiOiA1LAogICAgICAgICJlbGVtZW50SWRlbnRpZmllciI6ICJkb2N1bWVudF9udW1iZXIiLAogICAgICAgICJlbGVtZW50VmFsdWUiOiAiJHtkb2N1bWVudE51bWJlcn0iCiAgICAgIH0KICAgIF0KICB9LAogICJkb2NUeXBlIjogIiR7X2RvY3R5cGV9IiwKICAidmFsaWRpdHlJbmZvIjogewogICAgInZhbGlkRnJvbSI6ICIke192YWxpZEZyb219IiwKICAgICJ2YWxpZFVudGlsIjogIiR7X3ZhbGlkVW50aWx9IiwKICAgICAic2lnbmVkIjogIiR7X3NpZ25lZH0iICAgIAogIH0KfQ==',  -- the mso_mdoc VC template (namespace org.iso.18013.5.1)
           'org.iso.18013.5.1.mDL',  -- doctype
           NULL,  -- vct for SD-JWT VC
           NULL,  -- context (not applicable to mdoc)
           NULL,  -- credential_type (not applicable to mdoc)
           'mso_mdoc',  -- credential_format
           'did:web:approval-prescription-hormone-chan.trycloudflare.com',  -- did_url
           'CERTIFY_VC_SIGN_EC_R1',  -- key_manager_app_id
           'EC_SECP256R1_SIGN',  -- key_manager_ref_id
           'ES256',  -- signature_algo
           'EcdsaSecp256r1Signature2019',  -- signature_crypto_suite
           NULL,  -- sd_claim (not applicable to mdoc)
           '[{"name": "Mobile Driving License", "locale": "en", "logo": {"uri": "https://inji.github.io/inji-config/logos/mosipid-logo.png", "alt_text": "mosip-logo"}, "background_color": "#12107c", "text_color": "#FFFFFF", "background_image": {"uri": "https://inji.github.io/inji-config/logos/mosipid-logo.png"}}]'::JSONB,  -- display
           ARRAY['org.iso.18013.5.1~family_name', 'org.iso.18013.5.1~given_name', 'org.iso.18013.5.1~birth_date', 'org.iso.18013.5.1~document_number'],  -- display_order
           'sample_vc_mdoc',  -- scope
           ARRAY['did:jwk'],  -- cryptographic_binding_methods_supported (required, together with proof_types_supported below, for HolderBindingEvaluatorImpl to include deviceKeyInfo)
           ARRAY['ES256'],  -- credential_signing_alg_values_supported
           '{"jwt": {"proof_signing_alg_values_supported": ["ES256"]}}'::JSONB,  -- proof_types_supported
           NULL,  -- claims (mdoc uses mso_mdoc_claims instead)
           '{"org.iso.18013.5.1": {"family_name": {"display": [{"name": "Family Name", "locale": "en"}]}, "given_name": {"display": [{"name": "Given Name", "locale": "en"}]}, "birth_date": {"display": [{"name": "Date of Birth", "locale": "en"}]}, "document_number": {"display": [{"name": "Document Number", "locale": "en"}]}}}'::JSONB,  -- mso_mdoc_claims
           '[{"mosip.certify.mock.data-provider.csv.identifier-column": "id", "mosip.certify.mock.data-provider.csv.data-columns": "id,givenName,familyName,birthDate,documentNumber,portrait,drivingPrivileges", "mosip.certify.mock.data-provider.csv-registry-uri": "/home/mosip/config/driving_license_mosipid.csv"}]'::JSONB,  -- plugin_configurations
           NULL,  -- credential_status_purpose
           '[{"Given Name": "${givenName}", "Family Name": "${familyName}", "Document Number": "${documentNumber}"}]'::JSONB,  -- qr_settings
           'EdDSA',  -- qr_signature_algo
           NOW(),  -- cr_dtimes
           NULL  -- upd_dtimes
       );

INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('ROOT', 2920, 1125, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_SERVICE', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_PARTNER', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_VC_SIGN_RSA', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_VC_SIGN_ED25519', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('BASE', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_VC_SIGN_EC_K1', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_VC_SIGN_EC_R1', 1095, 60, 'NA', true, 'mosipadmin', now());

CREATE TYPE credential_status_enum AS ENUM ('AVAILABLE', 'FULL');

CREATE TABLE certify.status_list_credential (
                                                id VARCHAR(255) PRIMARY KEY,
                                                vc_document VARCHAR NOT NULL,
                                                credential_type VARCHAR(100) NOT NULL,
                                                status_purpose VARCHAR(100),
                                                capacity BIGINT,
                                                credential_status credential_status_enum,
                                                cr_dtimes timestamp NOT NULL default now(),
                                                upd_dtimes timestamp
);

CREATE INDEX IF NOT EXISTS idx_slc_status_purpose ON certify.status_list_credential(status_purpose);
CREATE INDEX IF NOT EXISTS idx_slc_credential_type ON certify.status_list_credential(credential_type);
CREATE INDEX IF NOT EXISTS idx_slc_credential_status ON certify.status_list_credential(credential_status);
CREATE INDEX IF NOT EXISTS idx_slc_cr_dtimes ON certify.status_list_credential(cr_dtimes);

CREATE TABLE certify.ledger (
                                id SERIAL PRIMARY KEY,
                                credential_id VARCHAR(255),
                                issuer_id VARCHAR(255) NOT NULL,
                                issuance_date TIMESTAMP NOT NULL,
                                expiration_date TIMESTAMP,
                                credential_type VARCHAR(100) NOT NULL,
                                indexed_attributes JSONB,
                                credential_status_details JSONB NOT NULL DEFAULT '[]'::jsonb,
                                cr_dtimes TIMESTAMP NOT NULL DEFAULT NOW(),

                                CONSTRAINT uq_ledger_tracked_credential_id UNIQUE (credential_id),
                                CONSTRAINT ensure_credential_status_details_is_array CHECK (jsonb_typeof(credential_status_details) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_ledger_credential_id ON certify.ledger(credential_id);
CREATE INDEX IF NOT EXISTS idx_ledger_issuer_id ON certify.ledger(issuer_id);
CREATE INDEX IF NOT EXISTS idx_ledger_credential_type ON certify.ledger(credential_type);
CREATE INDEX IF NOT EXISTS idx_ledger_issuance_date ON certify.ledger(issuance_date);
CREATE INDEX IF NOT EXISTS idx_ledger_expiration_date ON certify.ledger(expiration_date);
CREATE INDEX IF NOT EXISTS idx_ledger_cr_dtimes ON certify.ledger(cr_dtimes);
CREATE INDEX IF NOT EXISTS idx_gin_ledger_indexed_attrs ON certify.ledger USING GIN (indexed_attributes);
CREATE INDEX IF NOT EXISTS idx_gin_ledger_status_details ON certify.ledger USING GIN (credential_status_details);

CREATE TABLE IF NOT EXISTS certify.credential_status_transaction (
                                                                     transaction_log_id SERIAL PRIMARY KEY,
                                                                     credential_id VARCHAR(255),
    status_purpose VARCHAR(100),
    status_value boolean,
    status_list_credential_id VARCHAR(255),
    status_list_index BIGINT,
    cr_dtimes TIMESTAMP NOT NULL DEFAULT NOW(),
    processed_dtimes TIMESTAMP,
    is_processed BOOLEAN NOT NULL DEFAULT FALSE
    );

CREATE INDEX IF NOT EXISTS idx_cst_is_processed_created ON certify.credential_status_transaction (is_processed, cr_dtimes);

CREATE TABLE certify.status_list_available_indices (
                                                       id SERIAL PRIMARY KEY,
                                                       status_list_credential_id VARCHAR(255) NOT NULL,
                                                       list_index BIGINT NOT NULL,
                                                       is_assigned BOOLEAN NOT NULL DEFAULT FALSE,
                                                       cr_dtimes TIMESTAMP NOT NULL DEFAULT NOW(),
                                                       upd_dtimes TIMESTAMP,

                                                       CONSTRAINT fk_status_list_credential
                                                           FOREIGN KEY(status_list_credential_id)
                                                               REFERENCES certify.status_list_credential(id)
                                                               ON DELETE CASCADE
                                                               ON UPDATE CASCADE,

                                                       CONSTRAINT uq_list_id_and_index
                                                           UNIQUE (status_list_credential_id, list_index)
);

CREATE INDEX IF NOT EXISTS idx_sla_available_indices
    ON certify.status_list_available_indices (status_list_credential_id, is_assigned, list_index)
    WHERE is_assigned = FALSE;

CREATE INDEX IF NOT EXISTS idx_sla_status_list_credential_id ON certify.status_list_available_indices(status_list_credential_id);
CREATE INDEX IF NOT EXISTS idx_sla_is_assigned ON certify.status_list_available_indices(is_assigned);
CREATE INDEX IF NOT EXISTS idx_sla_list_index ON certify.status_list_available_indices(list_index);
CREATE INDEX IF NOT EXISTS idx_sla_cr_dtimes ON certify.status_list_available_indices(cr_dtimes);

CREATE TABLE IF NOT EXISTS certify.shedlock (
                                                name VARCHAR(64),
    lock_until TIMESTAMPTZ(3) NOT NULL,
    locked_at TIMESTAMPTZ(3) NOT NULL,
    locked_by VARCHAR(255) NOT NULL,
    PRIMARY KEY (name)
    );

CREATE TABLE IF NOT EXISTS certify.iar_session (
                                                   id SERIAL PRIMARY KEY,
                                                   auth_session VARCHAR(128) NOT NULL UNIQUE,
    transaction_id VARCHAR(64) NOT NULL,
    request_id VARCHAR(64),
    verify_nonce VARCHAR(64),
    expires_at TIMESTAMP NOT NULL,
    client_id VARCHAR(128),
    scope VARCHAR(128),
    authorization_code VARCHAR(128) UNIQUE,
    response_uri VARCHAR(512),
    code_challenge VARCHAR(128),
    code_challenge_method VARCHAR(10),
    code_issued_at TIMESTAMP,
    is_code_used BOOLEAN NOT NULL DEFAULT FALSE,
    code_used_at TIMESTAMP,
    cr_dtimes TIMESTAMP NOT NULL DEFAULT NOW(),
    identity_data TEXT
    );

CREATE INDEX IF NOT EXISTS idx_iar_session_auth_session ON certify.iar_session(auth_session);
CREATE INDEX IF NOT EXISTS idx_iar_session_authorization_code ON certify.iar_session(authorization_code);
CREATE INDEX IF NOT EXISTS idx_iar_session_request_id ON certify.iar_session(request_id);
CREATE INDEX IF NOT EXISTS idx_iar_session_expires_at ON certify.iar_session(expires_at);
CREATE INDEX IF NOT EXISTS idx_iar_session_authorization_code_used ON certify.iar_session(authorization_code, is_code_used) WHERE authorization_code IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_iar_session_scope ON certify.iar_session(scope);
CREATE INDEX IF NOT EXISTS idx_iar_session_transaction_id ON certify.iar_session(transaction_id);

-- =====================================================
-- inji-verify library tables (embedded in certify-service)
-- =====================================================

CREATE TABLE IF NOT EXISTS certify.authorization_request_details (
                                                                     request_id      character varying(40) NOT NULL,
    transaction_id  character varying(40) NOT NULL,
    authorization_details text NOT NULL,
    expires_at      bigint NOT NULL,
    CONSTRAINT pk_authorization_request_details PRIMARY KEY (request_id)
    );

CREATE INDEX IF NOT EXISTS idx_ard_transaction_id ON certify.authorization_request_details (transaction_id);

CREATE TABLE IF NOT EXISTS certify.presentation_definition (
                                                               id                      character varying(36) NOT NULL,
    input_descriptors       text NOT NULL,
    name                    character varying(500),
    purpose                 character varying(500),
    vp_format               text,
    submission_requirements text,
    CONSTRAINT pk_presentation_definition PRIMARY KEY (id)
    );

CREATE TABLE IF NOT EXISTS certify.vc_submission (
                                                     transaction_id character varying(40) NOT NULL,
    vc             text NOT NULL
    );

CREATE INDEX IF NOT EXISTS idx_vc_submission_transaction_id ON certify.vc_submission (transaction_id);

CREATE TABLE IF NOT EXISTS certify.vp_submission (
                                                     request_id              character varying(40) NOT NULL,
    vp_token                VARCHAR NULL,
    presentation_submission text NULL,
    error                   character varying(100) NULL,
    error_description       character varying(200) NULL,
    response_code           character varying(200) NULL,
    response_code_expiry_at TIMESTAMP WITH TIME ZONE NULL,
                                          response_code_used      boolean DEFAULT false,
                                          CONSTRAINT pk_vp_submission PRIMARY KEY (request_id),
    CONSTRAINT uq_vp_submission_response_code UNIQUE (response_code)
    );

CREATE INDEX IF NOT EXISTS idx_vp_submission_response_code ON certify.vp_submission (response_code);