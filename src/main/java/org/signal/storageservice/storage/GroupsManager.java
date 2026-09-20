/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.storage;

import com.google.cloud.bigtable.data.v2.BigtableDataClient;
import com.google.protobuf.ByteString;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange;
import org.signal.storageservice.storage.protos.groups.GroupChanges.GroupChangeState;
import javax.annotation.Nullable;

public class GroupsManager {

  private final GroupsStore store;

  public GroupsManager(BigtableDataClient client, String groupsTableId, String groupLogsTableId) {
    this(new BigtableGroupsStore(client, groupsTableId, groupLogsTableId));
  }

  public GroupsManager(GroupsStore store) {
    this.store = java.util.Objects.requireNonNull(store);
  }

  public CompletableFuture<Optional<Group>> getGroup(ByteString groupId) {
    return store.getGroup(groupId);
  }

  public CompletableFuture<Boolean> createGroup(ByteString groupId, Group group) {
    return store.createGroup(groupId, group);
  }

  public CompletableFuture<Optional<Group>> updateGroup(ByteString groupId, Group group) {
    return store.updateGroup(groupId, group)
                      .thenCompose(modified -> {
                        if (modified) return CompletableFuture.completedFuture(Optional.empty());
                        else          return getGroup(groupId).thenApply(result -> Optional.of(result.orElseThrow()));
                      });
  }

  public CompletableFuture<List<GroupChangeState>> getChangeRecords(ByteString groupId, Group group,
      @Nullable Integer maxSupportedChangeEpoch, boolean includeFirstState, boolean includeLastState,
      int fromVersionInclusive, int toVersionExclusive) {
    if (fromVersionInclusive >= toVersionExclusive) {
      throw new IllegalArgumentException("Version to read from (" + fromVersionInclusive + ") must be less than version to read to (" + toVersionExclusive + ")");
    }

    return store.getRecordsFromVersion(groupId, maxSupportedChangeEpoch, includeFirstState, includeLastState, fromVersionInclusive, toVersionExclusive, group.getVersion())
                        .thenApply(groupChangeStatesAndSeenCurrentVersion -> {
                          List<GroupChangeState> groupChangeStates = groupChangeStatesAndSeenCurrentVersion.first();
                          boolean seenCurrentVersion = groupChangeStatesAndSeenCurrentVersion.second();
                          if (isGroupInRange(group, fromVersionInclusive, toVersionExclusive) && !seenCurrentVersion && toVersionExclusive - 1 == group.getVersion()) {
                            groupChangeStates.add(GroupChangeState.newBuilder().setGroupState(group).build());
                          }
                          return groupChangeStates;
                        });
  }

  public CompletableFuture<Boolean> appendChangeRecord(ByteString groupId, int version, GroupChange change, Group state) {
    return store.append(groupId, version, change, state);
  }

  public CompletableFuture<Boolean> createWithChange(ByteString id, Group group, GroupChange change) {
    return store.createWithChange(id, group, change);
  }

  public CompletableFuture<Optional<Group>> updateWithChange(ByteString id, Group group, GroupChange change) {
    return store.updateWithChange(id, group, change);
  }

  private static boolean isGroupInRange(Group group, int fromVersionInclusive, int toVersionExclusive) {
    return fromVersionInclusive <= group.getVersion() && group.getVersion() < toVersionExclusive;
  }
}
