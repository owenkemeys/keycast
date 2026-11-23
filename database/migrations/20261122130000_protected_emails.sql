-- content-web: account email addresses encrypted under the master key, with a
-- keyed fingerprint (HMAC-SHA256) for login lookup.
--
-- Envelope scheme: one random email data key, stored only wrapped by the
-- KeyManager (file or KMS master key). The application fills
-- email_ciphertext and email_fingerprint for every row (backfill at startup
-- and after each write), and looks accounts up by fingerprint.
CREATE TABLE IF NOT EXISTS email_protection_keys (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    wrapped_key BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS email_ciphertext BYTEA;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_fingerprint BYTEA;

CREATE INDEX IF NOT EXISTS idx_users_tenant_email_fingerprint
    ON users (tenant_id, email_fingerprint)
    WHERE email_fingerprint IS NOT NULL;

-- A changed or removed address invalidates its protected copy, so a stale
-- ciphertext or fingerprint can never outlive the address it was made from.
CREATE OR REPLACE FUNCTION users_reset_email_protection() RETURNS trigger AS $$
BEGIN
    IF NEW.email IS DISTINCT FROM OLD.email
       AND NEW.email_ciphertext IS NOT DISTINCT FROM OLD.email_ciphertext THEN
        NEW.email_ciphertext := NULL;
        NEW.email_fingerprint := NULL;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS users_reset_email_protection ON users;
CREATE TRIGGER users_reset_email_protection
    BEFORE UPDATE OF email ON users
    FOR EACH ROW EXECUTE FUNCTION users_reset_email_protection();
