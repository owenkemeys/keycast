-- content-web: classify the protected-email columns for the support reader.
-- The wrapped email key, ciphertexts and fingerprints stay hidden; only the
-- key row's id and creation time are readable.
GRANT SELECT (id, created_at) ON public.email_protection_keys TO support_reader;
