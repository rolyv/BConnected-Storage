// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.storage;

import com.google.protobuf.ByteString;
import com.google.protobuf.Message;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;
import javax.sql.DataSource;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.groups.GroupPublicParams;
import org.signal.storageservice.auth.GroupUser;
import org.signal.storageservice.configuration.GroupConfiguration;
import org.signal.storageservice.groups.GroupValidator;
import org.signal.libsignal.zkgroup.profiles.ServerZkProfileOperations;
import org.signal.storageservice.storage.protos.authority.AuthorityRosterEntry;
import org.signal.storageservice.storage.protos.authority.AuthoritySnapshot;
import org.signal.storageservice.storage.protos.groups.AccessControl;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange;
import org.signal.storageservice.storage.protos.groups.Member;
import org.signal.storageservice.storage.protos.groups.MemberPendingProfileKey;

/**
 * Internal, deliberately unregistered service for new, clear-roster-owned groups. There is no HTTP
 * adapter, manifest signer, publication worker, or delivery authorization in this checkpoint.
 * ZK relationship checks never establish equivalence between a clear ACI and an encrypted principal.
 */
public final class GroupAuthority {
  /**
   * Trusted in-process boundary, NOT request fields. A future admission adapter must retain the
   * original account/device/enrollment proof. Checks must be local and nonblocking: no remote calls
   * while the SQL transaction holds locks. expiresAtNanos uses System.nanoTime, never wall time.
   * This interface alone is not an implemented cross-service admission protocol.
   */
  public interface AccountBinding {
    UUID aci();
    UUID enrollmentId();
    long approvalEpoch();
    long expiresAtNanos();
    void requireCurrent();
  }

  /** Caller binding from the future authenticated account gateway. */
  public interface Authorization extends AccountBinding {}

  public sealed interface Change permits Invite, Accept, SetRole, Remove, Announcements, Terminate {}
  /** Target binding must come from a trusted current account-directory projection, never request UUIDs. */
  public record Invite(AccountBinding target, ByteString principal) implements Change {
    public Invite { Objects.requireNonNull(target); Objects.requireNonNull(principal); }
  }
  public record Accept(ByteString presentation) implements Change {
    public Accept { Objects.requireNonNull(presentation); }
  }
  public record SetRole(UUID aci, Member.Role role) implements Change {
    public SetRole { Objects.requireNonNull(aci); Objects.requireNonNull(role); }
  }
  public record Remove(UUID aci) implements Change { public Remove { Objects.requireNonNull(aci); } }
  public record Announcements(boolean enabled) implements Change {}
  public record Terminate() implements Change {}

  public enum Failure { DENIED, CONFLICT, INVALID, EXPIRED, CORRUPT }
  public static final class Rejected extends RuntimeException {
    private final Failure reason;
    Rejected(Failure reason) { super("Group authority operation rejected: " + reason); this.reason = reason; }
    public Failure reason() { return reason; }
  }
  private static void require(boolean condition, Failure reason) { if (!condition) throw new Rejected(reason); }
  private static final long MAX_RECEIPT_NANOS = 4_000_000_000L;
  private static final int MAX_NATIVE_BYTES = 8 * 1024 * 1024;
  private final DataSource dataSource;
  private final Executor executor;
  private final ServerSecretParams serverSecretParams;
  private final GroupValidator validator;
  private final Clock clock;

  public GroupAuthority(DataSource dataSource, Executor executor, ServerSecretParams secretParams,
      GroupConfiguration configuration, Clock clock) {
    this.dataSource = Objects.requireNonNull(dataSource);
    this.executor = Objects.requireNonNull(executor);
    this.serverSecretParams = Objects.requireNonNull(secretParams);
    this.validator = new GroupValidator(new ServerZkProfileOperations(secretParams), configuration);
    this.clock = Objects.requireNonNull(clock);
  }

  // Capture identity and expiry once. No retry, self-write, or new proof may extend queued work.
  private record Receipt(AccountBinding original, UUID aci, UUID enrollment, long epoch, long deadline) {
    static Receipt capture(AccountBinding auth) {
      var receipt = new Receipt(auth, Objects.requireNonNull(auth.aci()),
          Objects.requireNonNull(auth.enrollmentId()), auth.approvalEpoch(), auth.expiresAtNanos());
      require(receipt.epoch >= 0 && receipt.epoch <= 9_007_199_254_740_991L, Failure.INVALID);
      receipt.check();
      require(receipt.deadline - System.nanoTime() <= MAX_RECEIPT_NANOS, Failure.INVALID);
      return receipt;
    }
    void check() {
      require(deadline - System.nanoTime() > 0, Failure.EXPIRED);
      original.requireCurrent();
      require(aci.equals(original.aci()) && enrollment.equals(original.enrollmentId()) && epoch == original.approvalEpoch(), Failure.DENIED);
      require(deadline - System.nanoTime() > 0, Failure.EXPIRED);
    }
    void timeout(Connection connection) throws SQLException {
      check();
      long millis = Math.max(1, (deadline - System.nanoTime()) / 1_000_000);
      try (var s = connection.prepareStatement("SELECT set_config('statement_timeout',?,true), set_config('lock_timeout',?,true)")) {
        s.setString(1, millis + "ms"); s.setString(2, millis + "ms"); s.execute();
      }
    }
  }
  @FunctionalInterface private interface Work<T> { T apply(Connection connection) throws Exception; }
  private static void check(Receipt receipt, Receipt target) {
    receipt.check(); if (target != null) target.check();
    require(receipt.deadline - System.nanoTime() > 0
        && (target == null || target.deadline - System.nanoTime() > 0), Failure.EXPIRED);
  }
  private static void timeout(Connection c, Receipt receipt, Receipt target) throws SQLException {
    check(receipt, target);
    (target != null && target.deadline - System.nanoTime() < receipt.deadline - System.nanoTime() ? target : receipt).timeout(c);
  }
  private <T> CompletableFuture<T> transaction(Receipt receipt, Receipt target, Work<T> work) {
    try {
      return CompletableFuture.supplyAsync(() -> {
        try {
          check(receipt, target);
          T result;
          try (var c = dataSource.getConnection()) {
            check(receipt, target);
            c.setAutoCommit(false);
            c.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
            try {
              timeout(c, receipt, target);
              result = work.apply(c);
              check(receipt, target);
              c.commit();
              check(receipt, target);
            } catch (Exception failure) {
              try { c.rollback(); } catch (SQLException rollback) { failure.addSuppressed(rollback); }
              throw failure;
            }
          }
          // A failure after commit suppresses the response; retry with a new proof and the same request ID.
          check(receipt, target);
          return result;
        } catch (Exception failure) { throw new CompletionException(failure); }
      }, executor);
    } catch (RuntimeException failure) { return CompletableFuture.failedFuture(failure); }
  }

  /** Create only an entirely unused namespace. The actual caller is the sole initial active admin. */
  public CompletableFuture<AuthoritySnapshot> create(Authorization auth, UUID requestId,
      GroupUser relationship, Group proposed) {
    try {
      var receipt = Receipt.capture(auth);
      Objects.requireNonNull(requestId);
      noUnknownFields(proposed);
      require(proposed.getSerializedSize() <= MAX_NATIVE_BYTES && proposed.getVersion() == 0
          && !proposed.getTerminated() && proposed.getMembersCount() == 1
          && proposed.getMembersPendingProfileKeyCount() == 0
          && proposed.getMembersPendingAdminApprovalCount() == 0 && proposed.getMembersBannedCount() == 0,
          Failure.INVALID);
      require(proposed.getMembers(0).getRole() == Member.Role.ADMINISTRATOR, Failure.INVALID);
      var params = new GroupPublicParams(proposed.getPublicKey().toByteArray());
      var id = ByteString.copyFrom(params.getGroupIdentifier().serialize());
      var member = validator.validateMember(proposed, proposed.getMembers(0));
      var nativeGroup = proposed.toBuilder().clearMembers().addMembers(member).build();
      requireRelationship(relationship, nativeGroup, member.getUserId());
      validateNative(nativeGroup, id);
      var roster = List.of(entry(receipt.aci, member.getUserId(), AuthorityRosterEntry.State.ACTIVE,
          Member.Role.ADMINISTRATOR, receipt.enrollment, receipt.epoch));
      var result = snapshot(id, 0, receipt.aci.toString(), nativeGroup, roster);
      byte[] digest = digest("CREATE", id, proposed.toByteArray(), receipt.enrollment, receipt.epoch);
      receipt.check();
      return transaction(receipt, null, c -> {
        lock(c, receipt, null, requestId, id);
        Optional<AuthoritySnapshot> current = read(c, id);
        Optional<AuthoritySnapshot> replay = replay(c, receipt, requestId, id, digest);
        if (replay.isPresent()) {
          require(current.isPresent(), Failure.CORRUPT);
          authorize(receipt, relationship, current.get(), true, false);
          return replay.get();
        }
        require(current.isEmpty(), Failure.CONFLICT);
        try (var s = c.prepareStatement("INSERT INTO group_storage.group_namespaces(group_id,owned,creator_aci) VALUES(?,true,?) ON CONFLICT DO NOTHING")) {
          s.setBytes(1, id.toByteArray()); s.setObject(2, receipt.aci);
          require(s.executeUpdate() == 1, Failure.CONFLICT);
        }
        try (var s = c.prepareStatement("INSERT INTO group_storage.groups(group_id,version,data,authority_owned) VALUES(?,0,?,true) ON CONFLICT DO NOTHING")) {
          s.setBytes(1, id.toByteArray()); s.setBytes(2, nativeGroup.toByteArray());
          require(s.executeUpdate() == 1, Failure.CONFLICT);
        }
        var actions = GroupChange.Actions.newBuilder().setVersion(0).setGroupId(id).setSourceUserId(member.getUserId()).build();
        persist(c, receipt, null, requestId, digest, "CREATE", result, signed(actions, 0));
        return result;
      });
    } catch (Exception failure) { return CompletableFuture.failedFuture(failure); }
  }

  /** Expected revision applies to both clear authority and native state; no arbitrary replacement API. */
  public CompletableFuture<AuthoritySnapshot> change(Authorization auth, UUID requestId,
      GroupUser relationship, ByteString id, long expectedRevision, Change change) {
    try {
      var receipt = Receipt.capture(auth);
      Objects.requireNonNull(requestId); Objects.requireNonNull(change); Objects.requireNonNull(id);
      require(expectedRevision >= 0 && id.size() == 32, Failure.INVALID);
      // Verify expensive native profile credentials before taking a database lock. Only accept uses it.
      final Member accepted;
      if (change instanceof Accept acceptance) {
        require(!acceptance.presentation.isEmpty() && acceptance.presentation.size() <= 2048, Failure.INVALID);
        var group = Group.newBuilder().setPublicKey(ByteString.copyFrom(relationship.getGroupPublicKey().serialize())).build();
        accepted = validator.validateMember(group, Member.newBuilder().setRole(Member.Role.DEFAULT)
            .setPresentation(acceptance.presentation).build());
      } else { accepted = null; }
      final Receipt invitee = change instanceof Invite invite ? Receipt.capture(invite.target) : null;
      byte[] digest = digest("CHANGE", id, changeBytes(expectedRevision, change, invitee), receipt.enrollment, receipt.epoch);
      receipt.check();
      return transaction(receipt, invitee, c -> {
        lock(c, receipt, invitee, requestId, id);
        if (invitee != null) invitee.check();
        var current = read(c, id).orElseThrow(() -> new Rejected(Failure.DENIED));
        boolean acceptance = change instanceof Accept;
        var caller = authorize(receipt, relationship, current, !acceptance, acceptance);
        var replay = replay(c, receipt, requestId, id, digest);
        if (replay.isPresent()) return replay.get();
        require(current.getRevision() == expectedRevision, Failure.CONFLICT);
        require(expectedRevision < 0xffff_ffffL, Failure.CONFLICT);
        var group = Group.parseFrom(current.getNativeGroup());
        var next = group.toBuilder().setVersion(group.getVersion() + 1);
        var roster = new ArrayList<>(current.getRosterList());
        var actions = GroupChange.Actions.newBuilder().setGroupId(id).setSourceUserId(caller.getDeclaredPrincipal())
            .setVersion(next.getVersion());
        int epoch = 0;
        switch (change) {
          case Invite invite -> {
            require(invite.principal.size() == caller.getDeclaredPrincipal().size(), Failure.INVALID);
            new org.signal.libsignal.zkgroup.groups.UuidCiphertext(invite.principal.toByteArray());
            require(roster.stream().noneMatch(e -> e.getAci().equals(invitee.aci.toString())
                || e.getDeclaredPrincipal().equals(invite.principal)), Failure.CONFLICT);
            var pending = MemberPendingProfileKey.newBuilder().setMember(Member.newBuilder().setUserId(invite.principal)
                .setRole(Member.Role.DEFAULT).setJoinedAtVersion(next.getVersion()))
                .setAddedByUserId(caller.getDeclaredPrincipal()).setTimestamp(clock.millis()).build();
            next.addMembersPendingProfileKey(pending);
            actions.addAddMembersPendingProfileKey(GroupChange.Actions.AddMemberPendingProfileKeyAction.newBuilder().setAdded(pending));
            roster.add(entry(invitee.aci, invite.principal, AuthorityRosterEntry.State.INVITED, Member.Role.DEFAULT, invitee.enrollment, invitee.epoch));
          }
          case Accept ignored -> {
            require(caller.getState() == AuthorityRosterEntry.State.INVITED, Failure.CONFLICT);
            require(accepted.getUserId().equals(caller.getDeclaredPrincipal()), Failure.DENIED);
            var member = accepted.toBuilder().setJoinedAtVersion(next.getVersion()).build();
            next.clearMembersPendingProfileKey().addAllMembersPendingProfileKey(group.getMembersPendingProfileKeyList()
                .stream().filter(e -> !e.getMember().getUserId().equals(member.getUserId())).toList()).addMembers(member);
            actions.addPromoteMembersPendingProfileKey(GroupChange.Actions.PromoteMemberPendingProfileKeyAction.newBuilder()
                .setUserId(member.getUserId()).setProfileKey(member.getProfileKey()));
            roster.remove(caller);
            roster.add(entry(receipt.aci, member.getUserId(), AuthorityRosterEntry.State.ACTIVE, Member.Role.DEFAULT, receipt.enrollment, receipt.epoch));
          }
          case SetRole role -> {
            require(role.role == Member.Role.DEFAULT || role.role == Member.Role.ADMINISTRATOR, Failure.INVALID);
            var target = find(roster, role.aci);
            require(target.getState() == AuthorityRosterEntry.State.ACTIVE && target.getRole() != role.role.getNumber(), Failure.CONFLICT);
            next.clearMembers().addAllMembers(group.getMembersList().stream().map(m -> m.getUserId().equals(target.getDeclaredPrincipal())
                ? m.toBuilder().setRole(role.role).build() : m).toList());
            actions.addModifyMemberRoles(GroupChange.Actions.ModifyMemberRoleAction.newBuilder().setUserId(target.getDeclaredPrincipal()).setRole(role.role));
            roster.set(roster.indexOf(target), target.toBuilder().setRole(role.role.getNumber()).build());
          }
          case Remove removal -> {
            var target = find(roster, removal.aci);
            roster.remove(target);
            if (target.getState() == AuthorityRosterEntry.State.ACTIVE) {
              next.clearMembers().addAllMembers(group.getMembersList().stream().filter(m -> !m.getUserId().equals(target.getDeclaredPrincipal())).toList());
              actions.addDeleteMembers(GroupChange.Actions.DeleteMemberAction.newBuilder().setDeletedUserId(target.getDeclaredPrincipal()));
            } else {
              next.clearMembersPendingProfileKey().addAllMembersPendingProfileKey(group.getMembersPendingProfileKeyList()
                  .stream().filter(m -> !m.getMember().getUserId().equals(target.getDeclaredPrincipal())).toList());
              actions.addDeleteMembersPendingProfileKey(GroupChange.Actions.DeleteMemberPendingProfileKeyAction.newBuilder().setDeletedUserId(target.getDeclaredPrincipal()));
            }
          }
          case Announcements policy -> {
            require(group.getAnnouncementsOnly() != policy.enabled, Failure.CONFLICT);
            next.setAnnouncementsOnly(policy.enabled);
            actions.setModifyAnnouncementsOnly(GroupChange.Actions.ModifyAnnouncementsOnlyAction.newBuilder().setAnnouncementsOnly(policy.enabled));
            epoch = 3;
          }
          case Terminate ignored -> {
            next.setTerminated(true);
            actions.setTerminateGroup(GroupChange.Actions.TerminateGroupAction.getDefaultInstance());
            epoch = 7;
          }
        }
        require(roster.stream().anyMatch(e -> e.getState() == AuthorityRosterEntry.State.ACTIVE
            && e.getRole() == Member.Role.ADMINISTRATOR.getNumber()), Failure.DENIED);
        var result = snapshot(id, expectedRevision + 1, current.getCreatorAci(), next.build(), roster);
        try (var s = c.prepareStatement("UPDATE group_storage.groups SET version=?,data=? WHERE group_id=? AND authority_owned AND version=?")) {
          s.setLong(1, result.getRevision()); s.setBytes(2, result.getNativeGroup().toByteArray());
          s.setBytes(3, id.toByteArray()); s.setLong(4, expectedRevision);
          require(s.executeUpdate() == 1, Failure.CORRUPT);
        }
        persist(c, receipt, invitee, requestId, digest, change.getClass().getSimpleName(), result, signed(actions.build(), epoch));
        if (invitee != null) invitee.check();
        return result;
      });
    } catch (Exception failure) { return CompletableFuture.failedFuture(failure); }
  }

  public CompletableFuture<AuthoritySnapshot> get(Authorization auth, GroupUser relationship, ByteString id) {
    try {
      var receipt = Receipt.capture(auth);
      require(id != null && id.size() == 32, Failure.INVALID);
      return transaction(receipt, null, c -> {
        PostgresStorage.lockGroup(c, id); receipt.check();
        var current = read(c, id).orElseThrow(() -> new Rejected(Failure.DENIED));
        authorize(receipt, relationship, current, false, false);
        return current;
      });
    } catch (Exception failure) { return CompletableFuture.failedFuture(failure); }
  }

  /** Historical commit acknowledgment only. It carries no current role, roster, or permission. */
  public record CommittedOutcome(ByteString groupId, long revision, ByteString nativeSha256) {}

  public CompletableFuture<Optional<CommittedOutcome>> outcome(Authorization auth, UUID requestId) {
    try {
      var receipt = Receipt.capture(auth);
      Objects.requireNonNull(requestId);
      return transaction(receipt, null, c -> {
        try (var s = c.prepareStatement("SELECT actor_enrollment_id,actor_approval_epoch,result FROM group_storage.group_authority_requests WHERE actor_aci=? AND request_id=?")) {
          s.setObject(1, receipt.aci); s.setObject(2, requestId);
          try (var rows = s.executeQuery()) {
            if (!rows.next()) return Optional.empty();
            require(receipt.enrollment.equals(rows.getObject(1, UUID.class)) && receipt.epoch == rows.getLong(2), Failure.DENIED);
            var result = AuthoritySnapshot.parseFrom(rows.getBytes(3));
            consistent(result);
            return Optional.of(new CommittedOutcome(result.getGroupId(), result.getRevision(), result.getNativeSha256()));
          }
        }
      });
    } catch (Exception failure) { return CompletableFuture.failedFuture(failure); }
  }

  private void lock(Connection c, Receipt receipt, Receipt target, UUID request, ByteString id) throws Exception {
    PostgresStorage.lock(c, "group_storage:authority_request", (receipt.aci + ":" + request).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    timeout(c, receipt, target);
    PostgresStorage.lockGroup(c, id);
    timeout(c, receipt, target);
  }

  private AuthorityRosterEntry authorize(Receipt receipt, GroupUser relationship, AuthoritySnapshot state,
      boolean admin, boolean invitationAllowed) throws Exception {
    receipt.check();
    var group = Group.parseFrom(state.getNativeGroup());
    require(!group.getTerminated(), Failure.DENIED);
    var caller = find(state.getRosterList(), receipt.aci);
    require(invitationAllowed || caller.getState() == AuthorityRosterEntry.State.ACTIVE, Failure.DENIED);
    require(caller.getEnrollmentId().equals(receipt.enrollment.toString()) && caller.getApprovalEpoch() == receipt.epoch, Failure.DENIED);
    require(!admin || caller.getRole() == Member.Role.ADMINISTRATOR.getNumber(), Failure.DENIED);
    requireRelationship(relationship, group, caller.getDeclaredPrincipal());
    return caller;
  }

  private static void requireRelationship(GroupUser user, Group group, ByteString principal) throws Exception {
    var params = new GroupPublicParams(group.getPublicKey().toByteArray());
    require(user.getGroupId().equals(ByteString.copyFrom(params.getGroupIdentifier().serialize()))
        && MessageDigest.isEqual(user.getGroupPublicKey().serialize(), params.serialize()) && user.aciMatches(principal), Failure.DENIED);
  }
  private static AuthorityRosterEntry find(List<AuthorityRosterEntry> entries, UUID aci) {
    return entries.stream().filter(e -> e.getAci().equals(aci.toString())).findFirst().orElseThrow(() -> new Rejected(Failure.DENIED));
  }
  private static AuthorityRosterEntry entry(UUID aci, ByteString principal, AuthorityRosterEntry.State state,
      Member.Role role, UUID enrollment, long epoch) {
    return AuthorityRosterEntry.newBuilder().setAci(aci.toString()).setDeclaredPrincipal(principal).setState(state)
        .setRole(role.getNumber()).setEnrollmentId(enrollment.toString()).setApprovalEpoch(epoch).build();
  }

  private void validateNative(Group group, ByteString id) {
    noUnknownFields(group);
    require(group.getSerializedSize() <= MAX_NATIVE_BYTES && validator.isValidDisappearingMessageTimer(group)
        && validator.isValidAvatarUrl(group.getAvatarUrl(), id), Failure.INVALID);
    // Unsupported native transitions stay closed: no invite link/PNI promotion/admin-pending/bans.
    require(group.getAccessControl().getMembers() == AccessControl.AccessRequired.ADMINISTRATOR
        && group.getAccessControl().getAttributes() == AccessControl.AccessRequired.ADMINISTRATOR
        && group.getAccessControl().getAddFromInviteLink() == AccessControl.AccessRequired.UNSATISFIABLE
        && group.getAccessControl().getMemberLabel() == AccessControl.AccessRequired.UNKNOWN
        && group.getInviteLinkPassword().isEmpty() && group.getMembersPendingAdminApprovalCount() == 0
        && group.getMembersBannedCount() == 0, Failure.INVALID);
    validator.validateFinalGroupState(group);
  }
  private AuthoritySnapshot snapshot(ByteString id, long revision, String creator, Group group,
      List<AuthorityRosterEntry> roster) throws Exception {
    validateNative(group, id);
    var result = AuthoritySnapshot.newBuilder().setGroupId(id).setRevision(revision).setCreatorAci(creator)
        .setNativeGroup(group.toByteString()).setNativeSha256(ByteString.copyFrom(sha256(group.toByteArray())))
        .addAllRoster(roster.stream().sorted(Comparator.comparing(AuthorityRosterEntry::getAci)).toList()).build();
    consistent(result);
    return result;
  }

  private void consistent(AuthoritySnapshot state) throws Exception {
    var group = Group.parseFrom(state.getNativeGroup());
    require(state.getRevision() >= 0 && state.getRevision() == Integer.toUnsignedLong(group.getVersion())
        && state.getGroupId().equals(ByteString.copyFrom(new GroupPublicParams(group.getPublicKey().toByteArray()).getGroupIdentifier().serialize()))
        && state.getNativeSha256().equals(ByteString.copyFrom(sha256(state.getNativeGroup().toByteArray())))
        && !state.getDirectoryListed(), Failure.CORRUPT);
    validateNative(group, state.getGroupId());
    var ids = new HashSet<String>(); var principals = new HashSet<ByteString>();
    var nativeActive = group.getMembersList().stream().collect(java.util.stream.Collectors.toMap(Member::getUserId, m -> m));
    var nativeInvited = group.getMembersPendingProfileKeyList().stream().collect(java.util.stream.Collectors.toMap(m -> m.getMember().getUserId(), m -> m.getMember()));
    int active = 0; int invited = 0; int admins = 0;
    for (var entry : state.getRosterList()) {
      UUID.fromString(entry.getAci()); UUID.fromString(entry.getEnrollmentId());
      require(entry.getApprovalEpoch() >= 0 && entry.getApprovalEpoch() <= 9_007_199_254_740_991L, Failure.CORRUPT);
      require(ids.add(entry.getAci()) && principals.add(entry.getDeclaredPrincipal()), Failure.CORRUPT);
      if (entry.getState() == AuthorityRosterEntry.State.ACTIVE) {
        active++;
        UUID.fromString(entry.getEnrollmentId());
        if (entry.getRole() == Member.Role.ADMINISTRATOR.getNumber()) admins++;
        var member = nativeActive.get(entry.getDeclaredPrincipal());
        require(member != null && member.getRoleValue() == entry.getRole() && member.getPresentation().isEmpty()
            && !member.getProfileKey().isEmpty(), Failure.CORRUPT);
      } else {
        require(entry.getState() == AuthorityRosterEntry.State.INVITED && !entry.getEnrollmentId().isEmpty()
            && entry.getRole() == Member.Role.DEFAULT.getNumber(), Failure.CORRUPT);
        invited++;
        var member = nativeInvited.get(entry.getDeclaredPrincipal());
        require(member != null && member.getRoleValue() == entry.getRole() && member.getPresentation().isEmpty()
            && member.getProfileKey().isEmpty(), Failure.CORRUPT);
      }
    }
    require(active == group.getMembersCount() && invited == group.getMembersPendingProfileKeyCount() && admins > 0, Failure.CORRUPT);
  }

  private Optional<AuthoritySnapshot> read(Connection c, ByteString id) throws Exception {
    try (var s = c.prepareStatement("SELECT a.snapshot,a.revision,a.native_sha256,g.data,g.version,n.creator_aci FROM group_storage.group_authority a JOIN group_storage.groups g USING(group_id) JOIN group_storage.group_namespaces n USING(group_id) WHERE a.group_id=? AND g.authority_owned AND n.owned")) {
      s.setBytes(1, id.toByteArray());
      try (var rows = s.executeQuery()) {
        if (!rows.next()) return Optional.empty();
        var state = AuthoritySnapshot.parseFrom(rows.getBytes(1));
        consistent(state);
        require(state.getGroupId().equals(id) && state.getRevision() == rows.getLong(2)
            && state.getNativeSha256().equals(ByteString.copyFrom(rows.getBytes(3)))
            && state.getNativeGroup().equals(ByteString.copyFrom(rows.getBytes(4)))
            && state.getRevision() == rows.getLong(5) && state.getCreatorAci().equals(rows.getObject(6).toString()), Failure.CORRUPT);
        var roster = new ArrayList<AuthorityRosterEntry>();
        try (var r = c.prepareStatement("SELECT aci,principal,state,role,enrollment_id,approval_epoch FROM group_storage.group_roster WHERE group_id=? ORDER BY aci::text")) {
          r.setBytes(1, id.toByteArray());
          try (var records = r.executeQuery()) {
            while (records.next()) roster.add(entry(records.getObject(1, UUID.class), ByteString.copyFrom(records.getBytes(2)),
                AuthorityRosterEntry.State.valueOf(records.getString(3)), Member.Role.forNumber(records.getInt(4)), records.getObject(5, UUID.class), records.getLong(6)));
          }
        }
        require(roster.equals(state.getRosterList()), Failure.CORRUPT);
        return Optional.of(state);
      }
    }
  }

  private Optional<AuthoritySnapshot> replay(Connection c, Receipt receipt, UUID request, ByteString id, byte[] digest) throws Exception {
    try (var s = c.prepareStatement("SELECT group_id,request_sha256,result FROM group_storage.group_authority_requests WHERE actor_aci=? AND request_id=?")) {
      s.setObject(1, receipt.aci); s.setObject(2, request);
      try (var rows = s.executeQuery()) {
        if (!rows.next()) return Optional.empty();
        require(id.equals(ByteString.copyFrom(rows.getBytes(1))) && MessageDigest.isEqual(digest, rows.getBytes(2)), Failure.CONFLICT);
        var result = AuthoritySnapshot.parseFrom(rows.getBytes(3)); consistent(result);
        return Optional.of(result);
      }
    }
  }

  private void persist(Connection c, Receipt receipt, Receipt target, UUID request, byte[] digest, String operation,
      AuthoritySnapshot snapshot, GroupChange change) throws Exception {
    timeout(c, receipt, target);
    byte[] id = snapshot.getGroupId().toByteArray();
    try (var s = c.prepareStatement("INSERT INTO group_storage.group_authority(group_id,revision,snapshot,native_sha256) VALUES(?,?,?,?) ON CONFLICT(group_id) DO UPDATE SET revision=excluded.revision,snapshot=excluded.snapshot,native_sha256=excluded.native_sha256")) {
      s.setBytes(1, id); s.setLong(2, snapshot.getRevision()); s.setBytes(3, snapshot.toByteArray()); s.setBytes(4, snapshot.getNativeSha256().toByteArray()); s.executeUpdate();
    }
    try (var s = c.prepareStatement("DELETE FROM group_storage.group_roster WHERE group_id=?")) { s.setBytes(1, id); s.executeUpdate(); }
    try (var s = c.prepareStatement("INSERT INTO group_storage.group_roster(group_id,aci,principal,state,role,enrollment_id,approval_epoch) VALUES(?,?,?,?,?,?,?)")) {
      for (var member : snapshot.getRosterList()) {
        s.setBytes(1, id); s.setObject(2, UUID.fromString(member.getAci())); s.setBytes(3, member.getDeclaredPrincipal().toByteArray());
        s.setString(4, member.getState().name()); s.setInt(5, member.getRole());
        s.setObject(6, UUID.fromString(member.getEnrollmentId())); s.setLong(7, member.getApprovalEpoch()); s.addBatch();
      }
      s.executeBatch();
    }
    try (var s = c.prepareStatement("INSERT INTO group_storage.group_logs(group_id,version,change,state) VALUES(?,?,?,?)")) {
      s.setBytes(1, id); s.setLong(2, snapshot.getRevision()); s.setBytes(3, change.toByteArray()); s.setBytes(4, snapshot.getNativeGroup().toByteArray()); s.executeUpdate();
    }
    try (var s = c.prepareStatement("INSERT INTO group_storage.group_authority_requests(actor_aci,request_id,group_id,request_sha256,result,actor_enrollment_id,actor_approval_epoch) VALUES(?,?,?,?,?,?,?)")) {
      s.setObject(1, receipt.aci); s.setObject(2, request); s.setBytes(3, id); s.setBytes(4, digest); s.setBytes(5, snapshot.toByteArray()); s.setObject(6, receipt.enrollment); s.setLong(7, receipt.epoch); s.executeUpdate();
    }
    try (var s = c.prepareStatement("INSERT INTO group_storage.group_authority_outbox(group_id,revision,actor_aci,operation,snapshot) VALUES(?,?,?,?,?)")) {
      s.setBytes(1, id); s.setLong(2, snapshot.getRevision()); s.setObject(3, receipt.aci); s.setString(4, operation); s.setBytes(5, snapshot.toByteArray()); s.executeUpdate();
    }
    check(receipt, target);
  }
  private GroupChange signed(GroupChange.Actions actions, int epoch) {
    byte[] bytes = actions.toByteArray();
    return GroupChange.newBuilder().setActions(ByteString.copyFrom(bytes)).setChangeEpoch(epoch)
        .setServerSignature(ByteString.copyFrom(serverSecretParams.sign(bytes).serialize())).build();
  }
  private static byte[] sha256(byte[] bytes) throws Exception { return MessageDigest.getInstance("SHA-256").digest(bytes); }
  private static byte[] digest(String domain, ByteString id, byte[] input, UUID enrollment, long epoch) throws Exception {
    var bytes = new ByteArrayOutputStream();
    try (var out = new DataOutputStream(bytes)) { out.writeUTF(domain); out.writeUTF(enrollment.toString()); out.writeLong(epoch); out.writeInt(id.size()); id.writeTo(out); out.writeInt(input.length); out.write(input); }
    return sha256(bytes.toByteArray());
  }
  private static byte[] changeBytes(long expected, Change change, Receipt target) throws Exception {
    var bytes = new ByteArrayOutputStream();
    try (var out = new DataOutputStream(bytes)) {
      out.writeLong(expected); out.writeUTF(change.getClass().getSimpleName());
      switch (change) {
        case Invite v -> { out.writeUTF(target.aci.toString()); out.writeUTF(target.enrollment.toString()); out.writeLong(target.epoch); out.writeInt(v.principal.size()); v.principal.writeTo(out); }
        case Accept v -> { out.writeInt(v.presentation.size()); v.presentation.writeTo(out); }
        case SetRole v -> { out.writeUTF(v.aci.toString()); out.writeInt(v.role.getNumber()); }
        case Remove v -> out.writeUTF(v.aci.toString());
        case Announcements v -> out.writeBoolean(v.enabled);
        case Terminate ignored -> {}
      }
    }
    return bytes.toByteArray();
  }
  private static void noUnknownFields(Message message) {
    require(message.getUnknownFields().asMap().isEmpty(), Failure.INVALID);
    for (var field : message.getAllFields().entrySet()) {
      if (field.getKey().getJavaType() != com.google.protobuf.Descriptors.FieldDescriptor.JavaType.MESSAGE) continue;
      if (field.getKey().isRepeated()) for (var nested : (List<?>) field.getValue()) noUnknownFields((Message) nested);
      else noUnknownFields((Message) field.getValue());
    }
  }
}
