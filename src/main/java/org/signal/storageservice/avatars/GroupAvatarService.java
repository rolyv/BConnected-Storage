// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.avatars;

import java.security.MessageDigest;
import java.time.Clock;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;
import java.util.function.Consumer;
import java.util.function.Supplier;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Response;
import org.apache.commons.codec.binary.Base64;
import org.signal.storageservice.auth.GroupUser;
import org.signal.storageservice.groups.GroupAuth;
import org.signal.storageservice.storage.GroupsManager;
import org.signal.storageservice.storage.protos.groups.AccessControl;
import org.signal.storageservice.storage.protos.groups.AvatarDownloadAttributes;
import org.signal.storageservice.storage.protos.groups.AvatarUploadAttributes;
import org.signal.storageservice.storage.protos.groups.Group;

/** Existing ZK/group authorization only; alumni entitlement must be integrated before public enrollment. */
public final class GroupAvatarService {
  private final GroupAvatarStorage storage;
  private final GroupsManager groups;
  private final Executor executor;
  private final Clock clock;

  public GroupAvatarService(GroupAvatarStorage storage, GroupsManager groups, Executor executor, Clock clock) {
    this.storage = java.util.Objects.requireNonNull(storage); this.groups = java.util.Objects.requireNonNull(groups);
    this.executor = java.util.Objects.requireNonNull(executor); this.clock = java.util.Objects.requireNonNull(clock);
  }

  public CompletableFuture<Response> upload(GroupUser user) {
    return issue(user, group -> {
      if (group.isPresent()) {
        if (!GroupAuth.isModifyAttributesAllowed(user, group.get())) throw new ForbiddenException();
        if (group.get().getTerminated()) throw new WebApplicationException(423);
      } // Preserve pre-creation upload by a valid group-scoped ZK principal.
    }, () -> storage.upload(user.getGroupId()));
  }

  public CompletableFuture<Response> download(GroupUser user, String objectId, String inviteLinkPassword) {
    final String key;
    try { key = GroupAvatarStorage.key(user.getGroupId(), objectId); }
    catch (IllegalArgumentException invalid) { throw new BadRequestException("Invalid avatar key"); }
    return issue(user, maybeGroup -> {
      Group group = maybeGroup.orElseThrow(NotFoundException::new);
      if (GroupAuth.isMember(user, group) || GroupAuth.isMemberPendingProfileKey(user, group)) return;
      // Invite previews may read only the current avatar, never arbitrary historical objects.
      if (!key.equals(group.getAvatarUrl()) || GroupAuth.isMemberBanned(user, group)) throw new ForbiddenException();
      if (!GroupAuth.isMemberPendingAdminApproval(user, group)) {
        byte[] password = inviteLinkPassword == null ? null : Base64.decodeBase64(inviteLinkPassword);
        if (password == null || password.length != 16
            || !MessageDigest.isEqual(password, group.getInviteLinkPassword().toByteArray())) throw new ForbiddenException();
        var access = group.getAccessControl().getAddFromInviteLink();
        if (access == AccessControl.AccessRequired.UNKNOWN || access == AccessControl.AccessRequired.UNSATISFIABLE)
          throw new ForbiddenException();
      }
      if (group.getTerminated()) throw new WebApplicationException(423);
    }, () -> storage.download(user.getGroupId(), objectId));
  }

  private CompletableFuture<Response> issue(GroupUser user, Consumer<Optional<Group>> authorization, Supplier<Object> operation) {
    return groups.getGroup(user.getGroupId()).thenCompose(original -> {
      authorization.accept(original);
      // Provider I/O is bounded separately from the PostgreSQL completion threads.
      return CompletableFuture.supplyAsync(operation, executor).thenCompose(capability ->
          groups.getGroup(user.getGroupId()).thenApply(current -> {
            if (original.isPresent() && current.isEmpty()) throw new ForbiddenException();
            authorization.accept(current); // Role, removal, link/password and termination may have changed while signing.
            long expires = capability instanceof AvatarUploadAttributes upload ? upload.getExpiresAt()
                : ((AvatarDownloadAttributes) capability).getExpiresAt();
            if (expires <= clock.instant().getEpochSecond()) throw new ServiceUnavailableException();
            return Response.ok(capability).header("Cache-Control", "no-store").build();
          }));
    }).exceptionally(failure -> {
      Throwable cause = failure;
      while (cause instanceof CompletionException && cause.getCause() != null) cause = cause.getCause();
      if (cause instanceof WebApplicationException response) throw response;
      // No provider URL, policy, credential or response body enters the public error/log path.
      throw new ServiceUnavailableException("Group avatar storage temporarily unavailable");
    });
  }
}
