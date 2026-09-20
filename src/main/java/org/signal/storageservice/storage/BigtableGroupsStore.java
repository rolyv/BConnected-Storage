// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.storage;

import com.google.cloud.bigtable.data.v2.BigtableDataClient;
import com.google.protobuf.ByteString;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import javax.annotation.Nullable;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange;
import org.signal.storageservice.storage.protos.groups.GroupChanges.GroupChangeState;
import org.signal.storageservice.util.Pair;

final class BigtableGroupsStore implements GroupsStore {
  private final GroupsTable groups;
  private final GroupLogTable logs;

  BigtableGroupsStore(BigtableDataClient client, String groupsId, String logsId) {
    groups = new GroupsTable(client, groupsId);
    logs = new GroupLogTable(client, logsId);
  }
  @Override public CompletableFuture<Optional<Group>> getGroup(ByteString id) { return groups.getGroup(id); }
  @Override public CompletableFuture<Boolean> createGroup(ByteString id, Group group) { return groups.createGroup(id, group); }
  @Override public CompletableFuture<Boolean> updateGroup(ByteString id, Group group) { return groups.updateGroup(id, group); }
  @Override public CompletableFuture<Boolean> append(ByteString id, int version, GroupChange change, Group state) {
    return logs.append(id, version, change, state);
  }
  @Override public CompletableFuture<Pair<List<GroupChangeState>, Boolean>> getRecordsFromVersion(ByteString id,
      @Nullable Integer maxEpoch, boolean firstState, boolean lastState, int from, int to, int currentVersion) {
    return logs.getRecordsFromVersion(id, maxEpoch, firstState, lastState, from, to, currentVersion);
  }
}
