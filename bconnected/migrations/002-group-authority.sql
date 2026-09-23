-- Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
-- Apply after 001 using the migration identity, before deploying the authority-aware binary.
-- Namespace reservations are permanent: never purge them to reclaim a group identifier.
CREATE TABLE IF NOT EXISTS group_storage.group_namespaces (
  group_id bytea PRIMARY KEY,
  owned boolean NOT NULL,
  creator_aci uuid,
  CHECK (owned = (creator_aci IS NOT NULL))
);
ALTER TABLE group_storage.groups ADD COLUMN IF NOT EXISTS authority_owned boolean NOT NULL DEFAULT false;
INSERT INTO group_storage.group_namespaces(group_id, owned)
  SELECT group_id, false FROM group_storage.groups ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION group_storage.reserve_group_namespace() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.group_id <> OLD.group_id OR NEW.authority_owned <> OLD.authority_owned THEN
      RAISE EXCEPTION 'Group namespace ownership is immutable';
    END IF;
  ELSE
    INSERT INTO group_storage.group_namespaces(group_id, owned) VALUES (NEW.group_id, false)
      ON CONFLICT DO NOTHING;
    IF NOT EXISTS (SELECT 1 FROM group_storage.group_namespaces
        WHERE group_id = NEW.group_id AND owned = NEW.authority_owned) THEN
      RAISE EXCEPTION 'Group namespace ownership conflict';
    END IF;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS reserve_group_namespace ON group_storage.groups;
CREATE TRIGGER reserve_group_namespace BEFORE INSERT OR UPDATE ON group_storage.groups
  FOR EACH ROW EXECUTE FUNCTION group_storage.reserve_group_namespace();

CREATE TABLE IF NOT EXISTS group_storage.group_authority (
  group_id bytea PRIMARY KEY REFERENCES group_storage.groups(group_id),
  revision bigint NOT NULL CHECK (revision >= 0),
  snapshot bytea NOT NULL,
  native_sha256 bytea NOT NULL CHECK (octet_length(native_sha256) = 32)
);
CREATE TABLE IF NOT EXISTS group_storage.group_roster (
  group_id bytea NOT NULL REFERENCES group_storage.group_authority(group_id),
  aci uuid NOT NULL,
  principal bytea NOT NULL CHECK (octet_length(principal) > 0),
  state text NOT NULL CHECK (state IN ('ACTIVE','INVITED')),
  role smallint NOT NULL CHECK (role IN (1,2)),
  enrollment_id uuid NOT NULL,
  approval_epoch bigint NOT NULL CHECK (approval_epoch BETWEEN 0 AND 9007199254740991),
  PRIMARY KEY (group_id, aci),
  UNIQUE (group_id, principal),
  CHECK (state = 'ACTIVE' OR role = 1)
);
CREATE TABLE IF NOT EXISTS group_storage.group_authority_requests (
  actor_aci uuid NOT NULL,
  actor_enrollment_id uuid NOT NULL,
  actor_approval_epoch bigint NOT NULL CHECK (actor_approval_epoch BETWEEN 0 AND 9007199254740991),
  request_id uuid NOT NULL,
  group_id bytea NOT NULL REFERENCES group_storage.group_authority(group_id),
  request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
  result bytea NOT NULL,
  PRIMARY KEY (actor_aci, request_id)
);
CREATE TABLE IF NOT EXISTS group_storage.group_authority_outbox (
  group_id bytea NOT NULL REFERENCES group_storage.group_authority(group_id),
  revision bigint NOT NULL CHECK (revision >= 0),
  actor_aci uuid NOT NULL,
  operation text NOT NULL,
  snapshot bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (group_id, revision)
);
