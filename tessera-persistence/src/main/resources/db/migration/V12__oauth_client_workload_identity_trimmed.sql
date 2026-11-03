-- V12 — a workload-identity client's issuer and subject are registered exactly as its token carries
-- them. The verifier compares `iss` and `sub` byte for byte, so a value registered with surrounding
-- white space, or empty, names no token at all: the client could never authenticate, and nothing
-- would say why. Registration is refused instead. `\s` covers spaces, tabs and line breaks.
--
-- The constraints are created valid: an existing row that breaks them fails the migration, which
-- names it, rather than leaving a client that silently cannot sign in.

ALTER TABLE oauth_client ADD CONSTRAINT ck_oauth_client_assertion_issuer_trimmed
    CHECK (assertion_issuer IS NULL OR (assertion_issuer <> '' AND assertion_issuer !~ '^\s|\s$'));
ALTER TABLE oauth_client ADD CONSTRAINT ck_oauth_client_assertion_subject_trimmed
    CHECK (assertion_subject IS NULL OR (assertion_subject <> '' AND assertion_subject !~ '^\s|\s$'));
