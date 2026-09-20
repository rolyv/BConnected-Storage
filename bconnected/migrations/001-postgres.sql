-- Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
-- Apply using a migration identity. Runtime requires USAGE on group_storage and DML on these four tables only.
CREATE SCHEMA IF NOT EXISTS group_storage;

CREATE TABLE IF NOT EXISTS group_storage.groups (
  group_id bytea PRIMARY KEY,
  version bigint NOT NULL CHECK (version BETWEEN 0 AND 4294967295),
  data bytea NOT NULL
);

CREATE TABLE IF NOT EXISTS group_storage.group_logs (
  group_id bytea NOT NULL REFERENCES group_storage.groups(group_id) ON DELETE CASCADE,
  version bigint NOT NULL CHECK (version BETWEEN 0 AND 4294967295),
  change bytea NOT NULL,
  state bytea NOT NULL,
  PRIMARY KEY (group_id, version)
);

CREATE TABLE IF NOT EXISTS group_storage.manifests (
  user_id uuid PRIMARY KEY,
  -- Protobuf uint64 is represented by Java's signed long; retain its complete bit pattern.
  version bigint NOT NULL,
  value bytea NOT NULL
);

CREATE TABLE IF NOT EXISTS group_storage.items (
  user_id uuid NOT NULL REFERENCES group_storage.manifests(user_id) ON DELETE CASCADE,
  item_key bytea NOT NULL,
  value bytea NOT NULL,
  PRIMARY KEY (user_id, item_key)
);
