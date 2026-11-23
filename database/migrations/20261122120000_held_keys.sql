-- content-web: held keys for outside accounts such as github:123456.
-- Generalises the vine_id preload column: one key per external account per
-- tenant, created by our server before the person arrives, and claimed when
-- they sign in with that account.
ALTER TABLE users ADD COLUMN IF NOT EXISTS external_id TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS held_key BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS external_claimed_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS held_profile_published_at TIMESTAMPTZ;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_id_tenant
    ON users (tenant_id, external_id)
    WHERE external_id IS NOT NULL;

-- Classified as readable by support, like vine_id.
GRANT SELECT (external_id, held_key, external_claimed_at, held_profile_published_at)
    ON public.users TO support_reader;
