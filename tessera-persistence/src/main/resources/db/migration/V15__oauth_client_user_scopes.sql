-- V15 — the scopes a client may request on the authorization-code grant, for tokens issued for a
-- person. Whitespace-separated, like allowed_scopes and audiences. Separate from allowed_scopes,
-- which holds what a confidential client receives for itself through client_credentials: a client
-- holding both grants must not get user tokens for scopes registered for its own behalf.
-- NULL means none: such a client may ask only for openid, which is always allowed. No existing row
-- is given scopes here; the operator registers them. The oauth_client RLS policy (V3) is
-- table-level and already governs this new column.

ALTER TABLE oauth_client ADD COLUMN user_scopes TEXT;

COMMENT ON COLUMN oauth_client.user_scopes IS
    'Whitespace-separated scopes the client may request on the authorization-code grant, besides openid; NULL for none.';
