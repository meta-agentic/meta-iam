-- V14 — a client's authentication method is one tessera knows, and a secret has one way to arrive.
--
-- CLIENT_SECRET meant "by HTTP Basic or in the body". A registration now names one, so such a row
-- moves to CLIENT_SECRET_BASIC, the default of RFC 6749 §2.3.1 and what the clients registered so far
-- send. Row-level security is lifted only inside this migration's transaction, because the update
-- crosses every tenant. A row the update missed fails the constraint, which stops the migration.

ALTER TABLE oauth_client NO FORCE ROW LEVEL SECURITY;
UPDATE oauth_client SET auth_method = 'CLIENT_SECRET_BASIC' WHERE auth_method = 'CLIENT_SECRET';
ALTER TABLE oauth_client FORCE ROW LEVEL SECURITY;

ALTER TABLE oauth_client ADD CONSTRAINT ck_oauth_client_auth_method_known
    CHECK (auth_method IS NULL OR auth_method IN (
        'MTLS', 'PRIVATE_KEY_JWT', 'WORKLOAD_IDENTITY', 'CLIENT_SECRET_BASIC', 'CLIENT_SECRET_POST'));
