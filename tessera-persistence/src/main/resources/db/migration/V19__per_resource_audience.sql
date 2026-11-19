-- V19 — per-resource access-token audience (ADR-IAM-009 D3), the columns the minting rules read.
--
-- oauth_client.user_audiences: the resources a token issued for a person may name, whitespace-
-- separated absolute URIs with no fragment, compared by exact string. Not null and empty for every
-- existing client: an empty list obtains no token for a person, so a client is given its list by
-- the operator before this release is deployed (the cut-over of ADR-IAM-009 D4). It is separate
-- from oauth_client.audiences, which stays with client_credentials; neither feeds the other.
--
-- oauth_client.resource_identifier: the resource a client is, for the audience comparison at
-- introspection (ADR-IAM-009 D3, ADR-IAM-007 D2 and D7). Nullable; read by a later release.
--
-- refresh_token_family.granted_resources: the whole resource set of the grant a family was issued
-- under (rule A2, RFC 8707 §2.2), space-separated. Nullable here: a family created before this
-- release has none and mints no token for a person. The cut-over migration, which deletes every
-- family, makes it not null.
--
-- The existing row-level-security policies of both tables (V3) are table-level and govern the new
-- columns. The statements touch no rows' tenant columns, so they need no tenant bound.
ALTER TABLE oauth_client
    ADD COLUMN user_audiences      TEXT NOT NULL DEFAULT '',
    ADD COLUMN resource_identifier TEXT;

ALTER TABLE refresh_token_family
    ADD COLUMN granted_resources TEXT;

COMMENT ON COLUMN oauth_client.user_audiences IS
    'Whitespace-separated resources (absolute URIs, no fragment) a token issued for a person may name; empty for none.';
COMMENT ON COLUMN oauth_client.resource_identifier IS
    'The resource this client is, for the audience comparison at introspection; NULL for none.';
COMMENT ON COLUMN refresh_token_family.granted_resources IS
    'Space-separated resources of the grant the family was issued under; NULL before they were recorded.';
