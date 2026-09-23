// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.storage;

import com.google.protobuf.ByteString;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;
import javax.annotation.Nullable;
import javax.sql.DataSource;
import org.signal.storageservice.auth.User;
import org.signal.storageservice.storage.protos.contacts.StorageItem;
import org.signal.storageservice.storage.protos.contacts.StorageManifest;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange;
import org.signal.storageservice.storage.protos.groups.GroupChanges.GroupChangeState;
import org.signal.storageservice.util.Pair;

/** Stores original encrypted protobuf bytes; group authentication and libsignal proofs are unchanged. */
public final class PostgresStorage implements GroupsStore, StorageStore {
  private final DataSource dataSource;
  private final Executor executor;

  public PostgresStorage(DataSource dataSource, Executor executor) {
    this.dataSource = java.util.Objects.requireNonNull(dataSource);
    this.executor = java.util.Objects.requireNonNull(executor);
  }

  @FunctionalInterface private interface SqlWork<T> { T apply(Connection connection) throws Exception; }

  private <T> CompletableFuture<T> transaction(SqlWork<T> work) {
    try {
      return CompletableFuture.supplyAsync(() -> {
        try (Connection connection = dataSource.getConnection()) {
          connection.setAutoCommit(false);
          try {
            T result = work.apply(connection);
            connection.commit();
            return result;
          } catch (Exception failure) {
            try { connection.rollback(); } catch (SQLException rollback) { failure.addSuppressed(rollback); }
            throw failure;
          }
        } catch (Exception e) {
          throw new CompletionException("PostgreSQL storage operation failed", e);
        }
      }, executor);
    } catch (RuntimeException e) {
      return CompletableFuture.failedFuture(e);
    }
  }

  static void lock(Connection connection, String namespace, byte[] identity) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    digest.update(namespace.getBytes(StandardCharsets.UTF_8));
    digest.update((byte) 0);
    long key = ByteBuffer.wrap(digest.digest(identity)).getLong();
    try (var statement = connection.prepareStatement("SELECT pg_advisory_xact_lock(?)")) {
      statement.setLong(1, key);
      statement.execute();
    }
  }

  static void lockGroup(Connection c, ByteString id) throws Exception {
    lock(c, "group_storage:group", id.toByteArray());
  }

  private static void lockUser(Connection c, User user) throws Exception {
    lock(c, "group_storage:user", user.getUuid().toString().getBytes(StandardCharsets.UTF_8));
  }

  @Override public CompletableFuture<Optional<Group>> getGroup(ByteString id) {
    return transaction(c -> readGroup(c, id));
  }

  private static Optional<Group> readGroup(Connection c, ByteString id) throws Exception {
    try (var s = c.prepareStatement("SELECT g.data,n.owned FROM group_storage.group_namespaces n LEFT JOIN group_storage.groups g USING(group_id) WHERE n.group_id=?")) {
      s.setBytes(1, id.toByteArray());
      try (var rows = s.executeQuery()) {
        if (!rows.next()) return Optional.empty();
        if (rows.getBoolean(2)) throw new IllegalStateException("Owned group requires account authorization");
        byte[] data = rows.getBytes(1);
        return data == null ? Optional.empty() : Optional.of(Group.parseFrom(data));
      }
    }
  }

  private static boolean insertGroup(Connection c, ByteString id, Group group) throws SQLException {
    try (var s = c.prepareStatement("INSERT INTO group_storage.groups(group_id,version,data) VALUES(?,?,?) ON CONFLICT DO NOTHING")) {
      s.setBytes(1, id.toByteArray());
      s.setLong(2, Integer.toUnsignedLong(group.getVersion()));
      s.setBytes(3, group.toByteArray());
      return s.executeUpdate() == 1;
    }
  }

  @Override public CompletableFuture<Boolean> createGroup(ByteString id, Group group) {
    return transaction(c -> { lockGroup(c, id); return insertGroup(c, id, group); });
  }

  private static boolean replaceGroup(Connection c, ByteString id, Group group) throws SQLException {
    try (var s = c.prepareStatement("UPDATE group_storage.groups SET version=?,data=? WHERE group_id=? AND version=? AND NOT authority_owned")) {
      s.setLong(1, Integer.toUnsignedLong(group.getVersion()));
      s.setBytes(2, group.toByteArray());
      s.setBytes(3, id.toByteArray());
      s.setLong(4, Integer.toUnsignedLong(group.getVersion() - 1));
      return s.executeUpdate() == 1;
    }
  }

  @Override public CompletableFuture<Boolean> updateGroup(ByteString id, Group group) {
    return transaction(c -> { lockGroup(c, id); return replaceGroup(c, id, group); });
  }

  private static boolean append(Connection c, ByteString id, int version, GroupChange change, Group state) throws SQLException {
    if (version != state.getVersion()) throw new IllegalArgumentException("Group log/state versions must match");
    try (var s = c.prepareStatement("INSERT INTO group_storage.group_logs(group_id,version,change,state) SELECT ?,?,?,? WHERE EXISTS (SELECT 1 FROM group_storage.groups WHERE group_id=? AND NOT authority_owned) ON CONFLICT DO NOTHING")) {
      s.setBytes(1, id.toByteArray());
      s.setLong(2, Integer.toUnsignedLong(version));
      s.setBytes(3, change.toByteArray());
      s.setBytes(4, state.toByteArray());
      s.setBytes(5, id.toByteArray());
      return s.executeUpdate() == 1;
    }
  }

  @Override public CompletableFuture<Boolean> append(ByteString id, int version, GroupChange change, Group state) {
    return transaction(c -> { lockGroup(c, id); return append(c, id, version, change, state); });
  }

  @Override public CompletableFuture<Boolean> createWithChange(ByteString id, Group group, GroupChange change) {
    return transaction(c -> {
      lockGroup(c, id);
      if (!insertGroup(c, id, group)) return false;
      if (!append(c, id, group.getVersion(), change, group)) throw new SQLException("Group log conflict");
      return true;
    });
  }

  @Override public CompletableFuture<Optional<Group>> updateWithChange(ByteString id, Group group, GroupChange change) {
    return transaction(c -> {
      lockGroup(c, id);
      if (!replaceGroup(c, id, group)) return Optional.of(readGroup(c, id).orElseThrow());
      if (!append(c, id, group.getVersion(), change, group)) throw new SQLException("Group log conflict");
      return Optional.empty();
    });
  }

  @Override public CompletableFuture<Pair<List<GroupChangeState>, Boolean>> getRecordsFromVersion(ByteString id,
      @Nullable Integer maxEpoch, boolean firstState, boolean lastState, int from, int to, int currentVersion) {
    return transaction(c -> {
      List<GroupChangeState> results = new ArrayList<>();
      boolean seenCurrent = false;
      try (var s = c.prepareStatement("SELECT change,state FROM group_storage.group_logs WHERE group_id=? AND version>=? AND version<? AND EXISTS (SELECT 1 FROM group_storage.groups g WHERE g.group_id=group_logs.group_id AND NOT g.authority_owned) ORDER BY version")) {
        s.setBytes(1, id.toByteArray());
        s.setLong(2, Integer.toUnsignedLong(from));
        s.setLong(3, Integer.toUnsignedLong(to));
        try (var rows = s.executeQuery()) {
          while (rows.next()) {
            GroupChange change = GroupChange.parseFrom(rows.getBytes(1));
            Group state = Group.parseFrom(rows.getBytes(2));
            seenCurrent |= state.getVersion() == currentVersion;
            var entry = GroupChangeState.newBuilder().setGroupChange(change);
            if (maxEpoch == null || maxEpoch < change.getChangeEpoch()
                || firstState && state.getVersion() == from || lastState && state.getVersion() == to - 1) {
              entry.setGroupState(state);
            }
            results.add(entry.build());
          }
        }
      }
      return new Pair<>(results, seenCurrent);
    });
  }

  private static Optional<StorageManifest> readManifest(Connection c, User user) throws SQLException {
    try (var s = c.prepareStatement("SELECT version,value FROM group_storage.manifests WHERE user_id=?")) {
      s.setObject(1, user.getUuid());
      try (var rows = s.executeQuery()) {
        return rows.next() ? Optional.of(StorageManifest.newBuilder().setVersion(rows.getLong(1))
            .setValue(ByteString.copyFrom(rows.getBytes(2))).build()) : Optional.empty();
      }
    }
  }

  @Override public CompletableFuture<Optional<StorageManifest>> getManifest(User user) {
    return transaction(c -> readManifest(c, user));
  }

  @Override public CompletableFuture<Optional<StorageManifest>> getManifestIfNotVersion(User user, long version) {
    return transaction(c -> readManifest(c, user).filter(manifest -> manifest.getVersion() != version));
  }

  @Override public CompletableFuture<Optional<StorageManifest>> set(User user, StorageManifest manifest,
      List<StorageItem> inserts, List<ByteString> deletes) {
    return write(user, manifest, inserts, deletes, false);
  }

  @Override public CompletableFuture<Optional<StorageManifest>> write(User user, StorageManifest manifest,
      List<StorageItem> inserts, List<ByteString> deletes, boolean clearAll) {
    List<StorageItem> stableInserts = List.copyOf(inserts);
    List<ByteString> stableDeletes = List.copyOf(deletes);
    return transaction(c -> {
      lockUser(c, user);
      Optional<StorageManifest> existing = readManifest(c, user);
      if (existing.isPresent() && existing.get().getVersion() != manifest.getVersion() - 1) return existing;
      try (var s = c.prepareStatement("INSERT INTO group_storage.manifests(user_id,version,value) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET version=excluded.version,value=excluded.value")) {
        s.setObject(1, user.getUuid()); s.setLong(2, manifest.getVersion()); s.setBytes(3, manifest.getValue().toByteArray());
        s.executeUpdate();
      }
      if (clearAll) clearItems(c, user);
      try (var insert = c.prepareStatement("INSERT INTO group_storage.items(user_id,item_key,value) VALUES(?,?,?) ON CONFLICT(user_id,item_key) DO UPDATE SET value=excluded.value");
           var delete = c.prepareStatement("DELETE FROM group_storage.items WHERE user_id=? AND item_key=?")) {
        int inserted = 0;
        for (StorageItem item : stableInserts) {
          insert.setObject(1, user.getUuid()); insert.setBytes(2, item.getKey().toByteArray());
          insert.setBytes(3, item.getValue().toByteArray()); insert.addBatch();
          if (++inserted % 1000 == 0) insert.executeBatch();
        }
        insert.executeBatch();
        int deleted = 0;
        for (ByteString key : stableDeletes) {
          delete.setObject(1, user.getUuid()); delete.setBytes(2, key.toByteArray()); delete.addBatch();
          if (++deleted % 1000 == 0) delete.executeBatch();
        }
        delete.executeBatch();
      }
      return Optional.empty();
    });
  }

  @Override public CompletableFuture<List<StorageItem>> getItems(User user, List<ByteString> keys) {
    if (keys.isEmpty()) throw new IllegalArgumentException("No keys");
    List<ByteString> stableKeys = keys.stream().distinct().sorted(ByteString.unsignedLexicographicalComparator()).toList();
    return transaction(c -> {
      List<StorageItem> result = new ArrayList<>();
      final var keyArray = c.createArrayOf("bytea", stableKeys.stream()
          .map(key -> "\\x" + java.util.HexFormat.of().formatHex(key.toByteArray())).toArray(String[]::new));
      try (var s = c.prepareStatement("SELECT item_key,value FROM group_storage.items WHERE user_id=? AND item_key=ANY(?) ORDER BY item_key")) {
          s.setObject(1, user.getUuid()); s.setArray(2, keyArray);
          try (var rows = s.executeQuery()) {
            while (rows.next()) result.add(StorageItem.newBuilder().setKey(ByteString.copyFrom(rows.getBytes(1)))
                .setValue(ByteString.copyFrom(rows.getBytes(2))).build());
          }
      } finally { keyArray.free(); }
      return result;
    });
  }

  private static void clearItems(Connection c, User user) throws SQLException {
    try (var s = c.prepareStatement("DELETE FROM group_storage.items WHERE user_id=?")) {
      s.setObject(1, user.getUuid()); s.executeUpdate();
    }
  }

  @Override public CompletableFuture<Void> clearItems(User user) {
    return transaction(c -> { lockUser(c, user); clearItems(c, user); return null; });
  }

  @Override public CompletableFuture<Void> delete(User user) {
    return transaction(c -> {
      lockUser(c, user);
      try (var s = c.prepareStatement("DELETE FROM group_storage.manifests WHERE user_id=?")) {
        s.setObject(1, user.getUuid()); s.executeUpdate();
      }
      return null;
    });
  }

  /** Checks all required tables every time; an open HTTP listener alone is not readiness. */
  public void checkReady() throws SQLException {
    try (Connection c = dataSource.getConnection(); var s = c.createStatement()) {
      for (String table : List.of("groups", "group_logs", "manifests", "items", "group_namespaces", "group_authority", "group_roster", "group_authority_requests", "group_authority_outbox")) {
        try (var rows = s.executeQuery("SELECT 1 FROM group_storage." + table + " LIMIT 1")) { rows.next(); }
      }
    }
  }
}
