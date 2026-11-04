-- V13 — the theme a client's hosted sign-in page shows (ADR-IAM-008 D2). Nullable: a client may
-- name none. Tessera reads it from the registration, never from a request. The name becomes part
-- of a URL path and a directory name, so the database refuses anything but the plain shape. The
-- oauth_client RLS policy (V3) is table-level and already governs this new column.

ALTER TABLE oauth_client
    ADD COLUMN sign_in_theme TEXT
    CONSTRAINT oauth_client_sign_in_theme_name CHECK (sign_in_theme ~ '^[a-z0-9][a-z0-9-]{0,62}$');

COMMENT ON COLUMN oauth_client.sign_in_theme IS
    'Name of the theme this client''s hosted sign-in page shows; NULL when it names none.';
