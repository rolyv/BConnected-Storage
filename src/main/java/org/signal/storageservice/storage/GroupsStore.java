// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.storage;

import com.google.protobuf.ByteString;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import javax.annotation.Nullable;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange;
import org.signal.storageservice.storage.protos.groups.GroupChanges.GroupChangeState;
import org.signal.storageservice.util.Pair;

/** Persistence only: authentication, encrypted group validation and signing remain in the existing controllers. */
public interface GroupsStore {
  CompletableFuture<Optional<Group>> getGroup(ByteString id);
  CompletableFuture<Boolean> createGroup(ByteString id, Group group);
  CompletableFuture<Boolean> updateGroup(ByteString id, Group group);
  CompletableFuture<Boolean> append(ByteString id, int version, GroupChange change, Group state);
  CompletableFuture<Pair<List<GroupChangeState>, Boolean>> getRecordsFromVersion(ByteString id,
      @Nullable Integer maxEpoch, boolean firstState, boolean lastState, int from, int to, int currentVersion);

  /** Native transactional stores override both combined writes. */
  default CompletableFuture<Boolean> createWithChange(ByteString id, Group group, GroupChange change) {
    return createGroup(id, group).thenCompose(created -> created ? append(id, group.getVersion(), change, group)
        : CompletableFuture.completedFuture(false));
  }

  default CompletableFuture<Optional<Group>> updateWithChange(ByteString id, Group group, GroupChange change) {
    return updateGroup(id, group).thenCompose(updated -> updated
        ? append(id, group.getVersion(), change, group).thenApply(ignored -> Optional.empty())
        : getGroup(id).thenApply(current -> Optional.of(current.orElseThrow())));
  }
}
