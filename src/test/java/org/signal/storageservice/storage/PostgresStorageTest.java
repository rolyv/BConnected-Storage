// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.storage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.google.protobuf.ByteString;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.signal.storageservice.auth.User;
import org.signal.storageservice.storage.protos.contacts.StorageItem;
import org.signal.storageservice.storage.protos.contacts.StorageManifest;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange;

class PostgresStorageTest {
  private PGSimpleDataSource dataSource;
  private ExecutorService executor;
  private PostgresStorage store;

  @BeforeEach void setup() throws Exception {
    String url = System.getenv("BCONNECTED_GROUP_TEST_JDBC_URL");
    assumeTrue(url != null, "Requires an isolated local PostgreSQL test fixture");
    URI uri = URI.create(url.substring("jdbc:".length()));
    if (!List.of("127.0.0.1", "localhost", "::1").contains(uri.getHost()) || !uri.getPath().endsWith("_test")) {
      throw new IllegalArgumentException("Only a loopback database ending in _test may run destructive storage tests");
    }
    dataSource = new PGSimpleDataSource();
    dataSource.setURL(url);
    dataSource.setUser("postgres");
    dataSource.setPassword(System.getenv("BCONNECTED_TEST_POSTGRES_PASSWORD"));
    try (var c = dataSource.getConnection(); var s = c.createStatement()) {
      s.execute(Files.readString(Path.of("bconnected/migrations/001-postgres.sql")));
      s.execute("ALTER TABLE group_storage.items DROP CONSTRAINT IF EXISTS test_reject_value");
      s.execute("TRUNCATE group_storage.groups,group_storage.group_logs,group_storage.manifests,group_storage.items");
    }
    executor = Executors.newFixedThreadPool(8);
    store = new PostgresStorage(dataSource, executor);
  }

  @AfterEach void teardown() { if (executor != null) executor.close(); }

  private static ByteString bytes(String value) { return ByteString.copyFromUtf8(value); }
  private static ByteString id() { return bytes(UUID.randomUUID().toString()); }
  private static Group group(int version, String value) {
    return Group.newBuilder().setVersion(version).setTitle(bytes(value)).setPublicKey(bytes("opaque-public-parameters"))
        .setDescription(bytes("opaque-encrypted-description")).build();
  }
  private static GroupChange change(int version, int epoch) {
    return GroupChange.newBuilder().setActions(GroupChange.Actions.newBuilder().setVersion(version).build().toByteString())
        .setServerSignature(bytes("opaque-signature-unchanged-by-storage")).setChangeEpoch(epoch).build();
  }
  private static StorageManifest manifest(long version, String value) {
    return StorageManifest.newBuilder().setVersion(version).setValue(bytes(value)).build();
  }
  private static StorageItem item(String key, String value) {
    return StorageItem.newBuilder().setKey(bytes(key)).setValue(bytes(value)).build();
  }

  @Test void groupCreationPreservesBytesAndWritesInitialLogOnce() {
    var id = id(); var state = group(0, "ciphertext\u0000\u00ff"); var delta = change(0, 0);
    assertThat(store.createWithChange(id, state, delta).join()).isTrue();
    assertThat(store.createWithChange(id, group(0, "other"), change(0, 1)).join()).isFalse();
    assertThat(store.getGroup(id).join()).contains(state);
    var log = store.getRecordsFromVersion(id, null, false, false, 0, 1, 0).join();
    assertThat(log.first()).hasSize(1);
    assertThat(log.first().getFirst().getGroupChange()).isEqualTo(delta);
    assertThat(log.first().getFirst().getGroupState()).isEqualTo(state);
    assertThat(log.second()).isTrue();
  }

  @Test void concurrentCreationHasExactlyOneWinnerAcrossStoreInstances() {
    var id = id(); var other = new PostgresStorage(dataSource, executor);
    var futures = new ArrayList<CompletableFuture<Boolean>>();
    for (int i = 0; i < 12; i++) futures.add((i % 2 == 0 ? store : other).createWithChange(id, group(0, "candidate-" + i), change(0, 0)));
    CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new)).join();
    assertThat(futures.stream().filter(CompletableFuture::join).count()).isEqualTo(1);
    assertThat(store.getRecordsFromVersion(id, null, false, false, 0, 1, 0).join().first().getFirst().getGroupState())
        .isEqualTo(store.getGroup(id).join().orElseThrow());
  }

  @Test void competingUpdatesCommitOneStateAndMatchingLog() {
    var id = id(); store.createWithChange(id, group(0, "initial"), change(0, 0)).join();
    var a = store.updateWithChange(id, group(1, "a"), change(1, 1));
    var b = new PostgresStorage(dataSource, executor).updateWithChange(id, group(1, "b"), change(1, 2));
    assertThat(List.of(a.join(), b.join()).stream().filter(java.util.Optional::isEmpty).count()).isEqualTo(1);
    var winner = store.getGroup(id).join().orElseThrow();
    assertThat(a.join().or(() -> b.join())).contains(winner);
    assertThat(store.getRecordsFromVersion(id, null, false, false, 1, 2, 1).join().first().getFirst().getGroupState()).isEqualTo(winner);
  }

  @Test void logConflictRollsBackGroupVersionAndData() {
    var id = id(); var original = group(0, "initial");
    store.createWithChange(id, original, change(0, 0)).join();
    store.append(id, 1, change(1, 9), group(1, "existing-log")).join();
    assertThatThrownBy(() -> store.updateWithChange(id, group(1, "must-rollback"), change(1, 0)).join()).hasCauseInstanceOf(java.sql.SQLException.class);
    assertThat(store.getGroup(id).join()).contains(original);
    assertThat(store.getRecordsFromVersion(id, null, false, false, 1, 2, 1).join().first().getFirst().getGroupState()).isEqualTo(group(1, "existing-log"));
  }

  @Test void logsAreImmutableOrderedAndRespectEpochAndStateFlags() {
    var id = id(); store.createWithChange(id, group(0, "0"), change(0, 0)).join();
    for (int i = 1; i < 4; i++) store.updateWithChange(id, group(i, "" + i), change(i, i == 2 ? 4 : 0)).join();
    assertThat(store.append(id, 2, change(2, 99), group(2, "overwrite")).join()).isFalse();
    var result = store.getRecordsFromVersion(id, 1, true, true, 0, 4, 3).join();
    assertThat(result.first()).extracting(entry -> entry.getGroupChange().getChangeEpoch()).containsExactly(0, 0, 4, 0);
    assertThat(result.first()).extracting(entry -> entry.hasGroupState()).containsExactly(true, false, true, true);
    assertThat(result.second()).isTrue();
    assertThat(store.getRecordsFromVersion(id, 99, false, false, 1, 3, 3).join().second()).isFalse();
  }

  @Test void managerRetainsCurrentStateFallbackAndGroupIsolation() {
    var id = id(); var otherId = id(); var state = group(2, "current-without-log");
    store.createGroup(id, state).join(); store.createWithChange(otherId, group(0, "other"), change(0, 0)).join();
    var manager = new GroupsManager(store);
    var records = manager.getChangeRecords(id, state, 9, false, false, 0, 3).join();
    assertThat(records).hasSize(1);
    assertThat(records.getFirst().hasGroupChange()).isFalse();
    assertThat(records.getFirst().getGroupState()).isEqualTo(state);
    assertThatThrownBy(() -> manager.getChangeRecords(id, state, 9, false, false, 3, 3)).isInstanceOf(IllegalArgumentException.class);
  }

  @Test void logRejectsMismatchedStateVersion() {
    var id = id(); store.createGroup(id, group(0, "state")).join();
    assertThatThrownBy(() -> store.append(id, 1, change(1, 0), group(0, "bad")).join()).hasCauseInstanceOf(IllegalArgumentException.class);
    assertThat(store.getRecordsFromVersion(id, null, false, false, 0, 2, 0).join().first()).isEmpty();
  }

  @Test void firstManifestAcceptsAnyVersionAndStaleWriteDoesNotMutateItems() {
    var user = new User(UUID.randomUUID()); var original = manifest(7, "ciphertext");
    assertThat(store.set(user, original, List.of(item("a", "value")), List.of()).join()).isEmpty();
    assertThat(store.write(user, manifest(7, "stale"), List.of(item("b", "bad")), List.of(bytes("a")), true).join()).contains(original);
    assertThat(store.getItems(user, List.of(bytes("a"), bytes("b"))).join()).containsExactly(item("a", "value"));
    assertThat(store.getManifestIfNotVersion(user, 7).join()).isEmpty();
    assertThat(store.getManifestIfNotVersion(user, 6).join()).contains(original);
  }

  @Test void manifestMutationAndClearAllCommitTogetherWithDeleteWinningOverlap() {
    var user = new User(UUID.randomUUID()); store.set(user, manifest(1, "old"), List.of(item("a", "old")), List.of()).join();
    assertThat(store.write(user, manifest(2, "new"), List.of(item("b", "new"), item("c", "delete-me")), List.of(bytes("c")), true).join()).isEmpty();
    assertThat(store.getItems(user, List.of(bytes("a"), bytes("b"), bytes("c"))).join()).containsExactly(item("b", "new"));
    assertThat(store.getManifest(user).join()).contains(manifest(2, "new"));
  }

  @Test void concurrentManifestUpdatesCannotMixWinnerAndLoserItems() {
    var user = new User(UUID.randomUUID()); store.set(user, manifest(1, "old"), List.of(), List.of()).join();
    var a = store.set(user, manifest(2, "a"), List.of(item("a", "a")), List.of());
    var b = new PostgresStorage(dataSource, executor).set(user, manifest(2, "b"), List.of(item("b", "b")), List.of());
    assertThat(List.of(a.join(), b.join()).stream().filter(java.util.Optional::isEmpty).count()).isEqualTo(1);
    String winner = store.getManifest(user).join().orElseThrow().getValue().toStringUtf8();
    assertThat(store.getItems(user, List.of(bytes("a"), bytes("b"))).join()).containsExactly(item(winner, winner));
  }

  @Test void lateItemFailureRollsBackManifestClearAndEarlierInserts() throws Exception {
    var user = new User(UUID.randomUUID()); var original = manifest(1, "original");
    store.set(user, original, List.of(item("old", "kept")), List.of()).join();
    try (var c = dataSource.getConnection(); var s = c.createStatement()) {
      s.execute("ALTER TABLE group_storage.items ADD CONSTRAINT test_reject_value CHECK(value<>decode('626164','hex'))");
    }
    assertThatThrownBy(() -> store.write(user, manifest(2, "rollback"), List.of(item("a", "fine"), item("b", "bad")), List.of(), true).join())
        .hasCauseInstanceOf(java.sql.SQLException.class);
    assertThat(store.getManifest(user).join()).contains(original);
    assertThat(store.getItems(user, List.of(bytes("old"), bytes("a"), bytes("b"))).join()).containsExactly(item("old", "kept"));
  }

  @Test void fullUint64ManifestBitPatternAndWrappingIncrementArePreserved() {
    var user = new User(UUID.randomUUID()); store.set(user, manifest(-1, "max-uint64"), List.of(), List.of()).join();
    assertThat(store.getManifest(user).join()).contains(manifest(-1, "max-uint64"));
    assertThat(store.set(user, manifest(0, "wrapped"), List.of(), List.of()).join()).isEmpty();
  }

  @Test void requestedKeysAreDeduplicatedSortedAndScopedToUser() {
    var a = new User(UUID.randomUUID()); var b = new User(UUID.randomUUID());
    store.set(a, manifest(1, "a"), List.of(item("b", "b"), item("a", "a")), List.of()).join();
    store.set(b, manifest(1, "b"), List.of(item("c", "private")), List.of()).join();
    assertThat(store.getItems(a, List.of(bytes("b"), bytes("a"), bytes("b"), bytes("c"))).join()).containsExactly(item("a", "a"), item("b", "b"));
    assertThatThrownBy(() -> store.getItems(a, List.of())).isInstanceOf(IllegalArgumentException.class);
  }

  @Test void clearPreservesManifestAndDeleteRemovesOnlyTheSelectedUser() {
    var a = new User(UUID.randomUUID()); var b = new User(UUID.randomUUID());
    store.set(a, manifest(1, "a"), List.of(item("x", "a")), List.of()).join();
    store.set(b, manifest(1, "b"), List.of(item("x", "b")), List.of()).join();
    store.clearItems(a).join(); assertThat(store.getManifest(a).join()).isPresent();
    store.delete(a).join(); store.delete(a).join();
    assertThat(store.getManifest(a).join()).isEmpty();
    assertThat(store.getItems(a, List.of(bytes("x"))).join()).isEmpty();
    assertThat(store.getItems(b, List.of(bytes("x"))).join()).containsExactly(item("x", "b"));
  }

  @Test void binaryKeysAndCiphertextRoundTripWithoutTextConversion() {
    var user = new User(UUID.randomUUID());
    ByteString key = ByteString.copyFrom(new byte[] {0, (byte) 0xff, '\\', '"', ',', '{', '}'});
    StorageItem item = StorageItem.newBuilder().setKey(key)
        .setValue(ByteString.copyFrom(new byte[] {(byte) 0xff, 0, (byte) 0x80, 1})).build();
    store.set(user, manifest(1, "manifest"), List.of(item), List.of()).join();
    assertThat(store.getItems(user, List.of(key)).join()).containsExactly(item);
  }

  @Test void readinessRequiresAllFourTables() throws Exception {
    store.checkReady();
    try (var c = dataSource.getConnection(); var s = c.createStatement()) {
      s.execute("ALTER TABLE group_storage.items RENAME TO items_readiness_test");
      try { assertThatThrownBy(store::checkReady).isInstanceOf(java.sql.SQLException.class); }
      finally { s.execute("ALTER TABLE group_storage.items_readiness_test RENAME TO items"); }
    }
  }
}
