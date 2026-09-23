// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.controllers;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.google.protobuf.ByteString;
import com.google.protobuf.UnknownFieldSet;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.zkgroup.NotarySignature;
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCredentialPresentation;
import org.signal.storageservice.avatars.GroupAvatarService;
import org.signal.storageservice.avatars.GroupAvatarStorage;
import org.signal.storageservice.auth.GroupUser;
import org.signal.storageservice.configuration.GroupConfiguration;
import org.signal.storageservice.storage.GroupAuthority;
import org.signal.storageservice.storage.GroupAuthority.*;
import org.signal.storageservice.storage.protos.authority.AuthoritySnapshot;
import org.signal.storageservice.storage.protos.authority.AuthorityRosterEntry;
import org.signal.storageservice.storage.protos.groups.*;

@EnabledIfEnvironmentVariable(named = "BCONNECTED_GROUP_TEST_JDBC_URL", matches = ".+")
class GroupAuthorityPostgresTest {
  final DisposableGroupDatabase db = new DisposableGroupDatabase();
  final SyntheticGroupFixture fixture = new SyntheticGroupFixture(3);
  final GroupConfiguration config = new GroupConfiguration(8000, 1024, 8192, new byte[32], null, null);
  final ExecutorService executor = Executors.newFixedThreadPool(8);
  final GroupAuthority service = service(db.dataSource, executor);
  final List<UUID> acis = fixture.identities.stream().map(identity -> ((Aci) identity).getRawUUID()).toList();
  final List<UUID> enrollments = List.of(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID());
  final List<GroupUser> users = List.of(fixture.authenticatedUser(0), fixture.authenticatedUser(1), fixture.authenticatedUser(2));
  final ByteString id = users.getFirst().getGroupId();
  final Group creation = fixture.submitted.toBuilder().clearMembers().addMembers(fixture.submitted.getMembers(0)).build();
  GroupAuthorityPostgresTest() throws Exception {}
  @AfterEach void cleanup() throws Exception { executor.close(); db.close(); }
  GroupAuthority service(DataSource source, Executor worker) {
    return new GroupAuthority(source, worker, fixture.server, config, Clock.systemUTC());
  }
  class Proof implements Authorization {
    final UUID aci;
    final UUID enrollment;
    final long deadline;
    long epoch = 1;
    volatile boolean revoked;
    Proof(int who) { this(acis.get(who), enrollments.get(who), 3900); }
    Proof(UUID aci, UUID enrollment, long millis) {
      this.aci = aci; this.enrollment = enrollment; deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(millis);
    }
    public UUID aci() { return aci; }
    public UUID enrollmentId() { return enrollment; }
    public long approvalEpoch() { return epoch; }
    public long expiresAtNanos() { return deadline; }
    public void requireCurrent() { if (revoked) throw new SecurityException("Synthetic account revoked"); }
  }
  Proof proof(int who) { return new Proof(who); }
  ByteString principal(int who) throws Exception {
    return ByteString.copyFrom(new ProfileKeyCredentialPresentation(fixture.submitted.getMembers(who).getPresentation().toByteArray())
        .getUuidCiphertext().serialize());
  }
  Invite invite(int who) throws Exception { return new Invite(proof(who), principal(who)); }
  AuthoritySnapshot create() { return service.create(proof(0), UUID.randomUUID(), users.getFirst(), creation).join(); }
  AuthoritySnapshot change(int who, long version, Change command) {
    return service.change(proof(who), UUID.randomUUID(), users.get(who), id, version, command).join();
  }
  AuthoritySnapshot current() { return service.get(proof(0), users.getFirst(), id).join(); }
  AuthoritySnapshot addMember() throws Exception {
    change(0, 0, invite(1));
    return change(1, 1, new Accept(fixture.submitted.getMembers(1).getPresentation()));
  }
  void reject(CompletableFuture<?> future, Failure reason) {
    assertThatThrownBy(future::join).isInstanceOf(CompletionException.class).hasCauseInstanceOf(Rejected.class)
        .satisfies(error -> assertThat(((Rejected) error.getCause()).reason()).isEqualTo(reason));
  }
  long count(String table) throws Exception {
    try (var c = db.dataSource.getConnection(); var s = c.createStatement(); var rs = s.executeQuery("SELECT count(*) FROM group_storage." + table)) {
      rs.next(); return rs.getLong(1);
    }
  }
  void sql(String text) throws Exception { try (var c = db.dataSource.getConnection(); var s = c.createStatement()) { s.execute(text); } }
  void assertCounts(long revisions, long roster) throws Exception {
    assertThat(count("groups")).isEqualTo(1); assertThat(count("group_authority")).isEqualTo(1);
    assertThat(count("group_namespaces")).isEqualTo(1); assertThat(count("group_roster")).isEqualTo(roster);
    assertThat(count("group_logs")).isEqualTo(revisions); assertThat(count("group_authority_requests")).isEqualTo(revisions);
    assertThat(count("group_authority_outbox")).isEqualTo(revisions);
  }
  void assertEmpty() throws Exception {
    for (String table : List.of("groups", "group_authority", "group_roster", "group_namespaces", "group_authority_requests", "group_authority_outbox", "group_logs")) assertThat(count(table)).isZero();
  }
  @Test void createCommitsExactNativeStateRosterHistoryIdempotencyAndOutbox() throws Exception {
    var state = create(); assertCounts(1, 1);
    assertThat(state.getCreatorAci()).isEqualTo(acis.getFirst().toString());
    assertThat(state.getRevision()).isZero(); assertThat(state.getDirectoryListed()).isFalse();
    assertThat(state.getNativeSha256().toByteArray()).isEqualTo(MessageDigest.getInstance("SHA-256").digest(state.getNativeGroup().toByteArray()));
    var group = Group.parseFrom(state.getNativeGroup());
    assertThat(group.getMembers(0).getPresentation()).isEmpty();
    assertThat(group.getMembers(0).getUserId()).isEqualTo(principal(0));
    assertThat(state.getRoster(0).getEnrollmentId()).isEqualTo(enrollments.getFirst().toString());
    assertThat(current()).isEqualTo(state);
    try (var c = db.dataSource.getConnection(); var s = c.createStatement(); var rows = s.executeQuery(
        "SELECT g.data,l.state,l.change,a.snapshot,o.snapshot,r.result FROM group_storage.groups g JOIN group_storage.group_logs l USING(group_id) JOIN group_storage.group_authority a USING(group_id) JOIN group_storage.group_authority_outbox o USING(group_id) JOIN group_storage.group_authority_requests r USING(group_id)")) {
      assertThat(rows.next()).isTrue(); assertThat(rows.getBytes(1)).isEqualTo(state.getNativeGroup().toByteArray());
      assertThat(rows.getBytes(2)).isEqualTo(rows.getBytes(1));
      var delta = GroupChange.parseFrom(rows.getBytes(3)); var actions = GroupChange.Actions.parseFrom(delta.getActions());
      assertThat(actions.getGroupId()).isEqualTo(id); assertThat(actions.getSourceUserId()).isEqualTo(principal(0));
      fixture.server.getPublicParams().verifySignature(delta.getActions().toByteArray(), new NotarySignature(delta.getServerSignature().toByteArray()));
      assertThat(rows.getBytes(4)).isEqualTo(state.toByteArray());
      assertThat(rows.getBytes(5)).isEqualTo(rows.getBytes(4)); assertThat(rows.getBytes(6)).isEqualTo(rows.getBytes(4));
    }
  }
  @Test void typedInvitationSelfAcceptanceRolePolicyRemovalPreserveStructuralEquality() throws Exception {
    create(); var accepted = addMember();
    assertThat(accepted.getRevision()).isEqualTo(2); assertThat(Group.parseFrom(accepted.getNativeGroup()).getMembersCount()).isEqualTo(2);
    assertThat(accepted.getRosterList()).allMatch(e -> e.getState() == AuthorityRosterEntry.State.ACTIVE);
    change(0, 2, new SetRole(acis.get(1), Member.Role.ADMINISTRATOR)); change(1, 3, new Announcements(false));
    var removed = change(1, 4, new Remove(acis.get(0)));
    assertThat(removed.getRevision()).isEqualTo(5); assertThat(removed.getRoster(0).getAci()).isEqualTo(acis.get(1).toString());
    assertThat(Group.parseFrom(removed.getNativeGroup()).getMembers(0).getUserId()).isEqualTo(principal(1));
    reject(service.get(proof(0), users.get(0), id), Failure.DENIED); assertCounts(6, 1);
  }
  @ParameterizedTest @ValueSource(strings = {"two-active", "non-admin", "version", "terminated", "invite-link", "member-access", "unknown", "profile"})
  void creationRejectsUnsupportedOrMalformedState(String kind) throws Exception {
    var invalid = creation.toBuilder();
    switch (kind) {
      case "two-active" -> invalid.addMembers(fixture.submitted.getMembers(1));
      case "non-admin" -> invalid.setMembers(0, invalid.getMembers(0).toBuilder().setRole(Member.Role.DEFAULT));
      case "version" -> invalid.setVersion(1);
      case "terminated" -> invalid.setTerminated(true);
      case "invite-link" -> invalid.setInviteLinkPassword(ByteString.copyFrom(new byte[16]));
      case "member-access" -> invalid.setAccessControl(invalid.getAccessControl().toBuilder().setMembers(AccessControl.AccessRequired.MEMBER));
      case "unknown" -> invalid.setUnknownFields(UnknownFieldSet.newBuilder().addField(999, UnknownFieldSet.Field.newBuilder().addVarint(1).build()).build());
      case "profile" -> invalid.setMembers(0, invalid.getMembers(0).toBuilder().setPresentation(ByteString.copyFromUtf8("invalid")));
    }
    assertThatThrownBy(() -> service.create(proof(0), UUID.randomUUID(), users.get(0), invalid.build()).join()).isInstanceOf(CompletionException.class);
    assertEmpty();
  }
  @Test void currentCallerMustMatchClearRosterAndNativeRelationshipIndependently() throws Exception {
    create(); reject(service.get(proof(1), users.get(0), id), Failure.DENIED); reject(service.get(proof(0), users.get(1), id), Failure.DENIED);
    reject(service.get(new Proof(acis.get(0), UUID.randomUUID(), 3900), users.get(0), id), Failure.DENIED);
    change(0, 0, invite(1));
    reject(service.change(proof(0), UUID.randomUUID(), users.get(0), id, 1, new Accept(fixture.submitted.getMembers(1).getPresentation())), Failure.CONFLICT);
    reject(service.change(proof(1), UUID.randomUUID(), users.get(1), id, 1, new Accept(fixture.submitted.getMembers(2).getPresentation())), Failure.DENIED);
    reject(service.change(proof(1), UUID.randomUUID(), users.get(1), id, 1, new Announcements(false)), Failure.DENIED); assertCounts(2, 2);
  }
  @Test void oldInvitationCannotBeAcceptedAfterTargetReenrollment() throws Exception {
    create(); change(0, 0, invite(1));
    var reapproved = new Proof(acis.get(1), UUID.randomUUID(), 3900);
    reject(service.change(reapproved, UUID.randomUUID(), users.get(1), id, 1, new Accept(fixture.submitted.getMembers(1).getPresentation())), Failure.DENIED);
    assertThat(current().getRosterList()).filteredOn(e -> e.getAci().equals(acis.get(1).toString()))
        .allMatch(e -> e.getState() == AuthorityRosterEntry.State.INVITED && e.getEnrollmentId().equals(enrollments.get(1).toString())); assertCounts(2, 2);
  }
  @Test void revokedTargetDirectoryProofCannotCreateInvitation() throws Exception {
    create(); var target = proof(1); target.revoked = true;
    assertThatThrownBy(() -> change(0, 0, new Invite(target, principal(1)))).hasRootCauseInstanceOf(SecurityException.class); assertCounts(1, 1);
  }
  @Test void creatorIsActualCallerNotAnIdentityInferredFromZk() throws Exception {
    var actual = new Proof(UUID.randomUUID(), UUID.randomUUID(), 3900);
    var state = service.create(actual, UUID.randomUUID(), users.get(0), creation).join();
    assertThat(state.getCreatorAci()).isEqualTo(actual.aci.toString()); assertThat(state.getRoster(0).getAci()).isEqualTo(actual.aci.toString());
    assertThat(state.getRoster(0).getDeclaredPrincipal()).isEqualTo(principal(0)); reject(service.get(proof(0), users.get(0), id), Failure.DENIED);
  }
  @Test void duplicateClearIdentityOrCiphertextAndLastAdminLossAreRejected() throws Exception {
    var first = create();
    reject(service.change(proof(0), UUID.randomUUID(), users.get(0), id, 0, new Invite(proof(0), principal(1))), Failure.CONFLICT);
    reject(service.change(proof(0), UUID.randomUUID(), users.get(0), id, 0, new Invite(proof(1), principal(0))), Failure.CONFLICT);
    reject(service.change(proof(0), UUID.randomUUID(), users.get(0), id, 0, new SetRole(acis.get(0), Member.Role.DEFAULT)), Failure.DENIED);
    reject(service.change(proof(0), UUID.randomUUID(), users.get(0), id, 0, new Remove(acis.get(0))), Failure.DENIED);
    assertThat(current()).isEqualTo(first); assertCounts(1, 1);
  }
  @Test void terminationIsPermanentAndNamespaceCannotBeClaimedAgain() throws Exception {
    create(); var state = change(0, 0, new Terminate()); assertThat(Group.parseFrom(state.getNativeGroup()).getTerminated()).isTrue();
    reject(service.change(proof(0), UUID.randomUUID(), users.get(0), id, 1, new Announcements(false)), Failure.DENIED);
    reject(service.create(proof(0), UUID.randomUUID(), users.get(0), creation), Failure.CONFLICT); assertCounts(2, 1);
  }
  @ParameterizedTest @ValueSource(booleans = {false, true})
  void existingLegacyGroupAndDeletedLegacyReservationCannotBeAdopted(boolean deleted) throws Exception {
    assertThat(db.storage.createWithChange(id, creation, GroupChange.getDefaultInstance()).join()).isTrue();
    if (deleted) sql("DELETE FROM group_storage.groups");
    reject(service.create(proof(0), UUID.randomUUID(), users.get(0), creation), Failure.CONFLICT);
    assertThat(count("group_authority")).isZero(); assertThat(count("group_namespaces")).isEqualTo(1);
  }
  @Test void ownedLegacyReadsWritesHistoryAndAvatarSigningFailClosed() throws Exception {
    var initial = create();
    assertThatThrownBy(() -> db.storage.getGroup(id).join()).hasRootCauseInstanceOf(IllegalStateException.class);
    assertThat(db.storage.updateGroup(id, creation.toBuilder().setVersion(1).build()).join()).isFalse();
    assertThat(db.storage.append(id, 1, GroupChange.getDefaultInstance(), creation.toBuilder().setVersion(1).build()).join()).isFalse();
    assertThat(db.storage.getRecordsFromVersion(id, null, true, true, 0, 2, 0).join().first()).isEmpty();
    assertThatThrownBy(() -> db.storage.createGroup(id, creation).join()).isInstanceOf(CompletionException.class);
    assertThatThrownBy(() -> db.storage.updateWithChange(id, creation.toBuilder().setVersion(1).build(), GroupChange.getDefaultInstance()).join()).isInstanceOf(CompletionException.class);
    var provider = mock(GroupAvatarStorage.class); var avatars = new GroupAvatarService(provider, db.manager, executor, Clock.systemUTC());
    assertThatThrownBy(() -> avatars.upload(users.get(0)).join()).hasRootCauseInstanceOf(jakarta.ws.rs.ServiceUnavailableException.class);
    verifyNoInteractions(provider); assertThat(current()).isEqualTo(initial); assertCounts(1, 1);
  }
  @Test void exactReplayReturnsCommittedBytesAndChangedRequestConflicts() throws Exception {
    var request = UUID.randomUUID(); var first = service.create(proof(0), request, users.get(0), creation).join();
    assertThat(service.create(proof(0), request, users.get(0), creation).join()).isEqualTo(first);
    reject(service.create(proof(0), request, users.get(0), creation.toBuilder().setDescription(ByteString.copyFromUtf8("different encrypted bytes")).build()), Failure.CONFLICT);
    var inviteRequest = UUID.randomUUID(); var second = service.change(proof(0), inviteRequest, users.get(0), id, 0, invite(1)).join();
    assertThat(service.change(proof(0), inviteRequest, users.get(0), id, 0, invite(1)).join()).isEqualTo(second);
    reject(service.change(proof(0), inviteRequest, users.get(0), id, 1, invite(1)), Failure.CONFLICT); assertCounts(2, 2);
  }
  @Test void replayRequiresCurrentAuthorityAndEnrollment() throws Exception {
    var request = UUID.randomUUID(); service.create(proof(0), request, users.get(0), creation).join();
    reject(service.create(new Proof(acis.get(0), UUID.randomUUID(), 3900), request, users.get(0), creation), Failure.CONFLICT);
    addMember(); change(0, 2, new SetRole(acis.get(1), Member.Role.ADMINISTRATOR)); change(1, 3, new SetRole(acis.get(0), Member.Role.DEFAULT));
    reject(service.create(proof(0), request, users.get(0), creation), Failure.DENIED); assertCounts(5, 2);
  }
  @Test void concurrentCreatorsHaveExactlyOneOwnerAndNoOrphans() throws Exception {
    var outcomes = new ArrayList<CompletableFuture<AuthoritySnapshot>>();
    for (int i = 0; i < 8; i++) outcomes.add(service.create(new Proof(UUID.randomUUID(), UUID.randomUUID(), 3900), UUID.randomUUID(), users.get(0), creation));
    CompletableFuture.allOf(outcomes.stream().map(f -> f.handle((r, e) -> null)).toArray(CompletableFuture[]::new)).join();
    assertThat(outcomes.stream().filter(f -> !f.isCompletedExceptionally()).count()).isEqualTo(1); assertCounts(1, 1);
  }
  @Test void concurrentExpectedRevisionWritersAndIdenticalRetriesCommitOnce() throws Exception {
    create(); var request = UUID.randomUUID(); var command = new Announcements(false); var futures = new ArrayList<CompletableFuture<AuthoritySnapshot>>();
    for (int i = 0; i < 8; i++) futures.add(service(db.dataSource, executor).change(proof(0), request, users.get(0), id, 0, command));
    CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new)).join();
    assertThat(futures.stream().map(CompletableFuture::join).distinct().count()).isEqualTo(1); assertCounts(2, 1);
    var a = service.change(proof(0), UUID.randomUUID(), users.get(0), id, 1, invite(1));
    var b = service.change(proof(0), UUID.randomUUID(), users.get(0), id, 1, invite(2));
    CompletableFuture.allOf(a.handle((r,e) -> null), b.handle((r,e) -> null)).join();
    assertThat(List.of(a,b).stream().filter(f -> !f.isCompletedExceptionally()).count()).isEqualTo(1); assertCounts(3, 2);
  }
  @ParameterizedTest @ValueSource(booleans = {false, true})
  void finalOutboxFailureRollsBackEveryEarlierWrite(boolean update) throws Exception {
    AuthoritySnapshot initial = update ? create() : null;
    sql("ALTER TABLE group_storage.group_authority_outbox ADD CONSTRAINT reject_synthetic_outbox CHECK (revision < " + (update ? 1 : 0) + ")");
    var future = update ? service.change(proof(0), UUID.randomUUID(), users.get(0), id, 0, invite(1)) : service.create(proof(0), UUID.randomUUID(), users.get(0), creation);
    assertThatThrownBy(future::join).hasCauseInstanceOf(java.sql.SQLException.class);
    if (update) { assertThat(current()).isEqualTo(initial); assertCounts(1, 1); } else assertEmpty();
  }
  @Test void corruptProjectionIsDeniedBeforeMutation() throws Exception {
    create(); sql("UPDATE group_storage.group_roster SET role=1");
    reject(service.change(proof(0), UUID.randomUUID(), users.get(0), id, 0, new Announcements(false)), Failure.CORRUPT); assertCounts(1, 1);
  }
  @Test void accountRevocationWhileWaitingForSqlLockPreventsMutation() throws Exception {
    create(); var proof = proof(0);
    try (var connection = db.dataSource.getConnection()) {
      connection.setAutoCommit(false);
      var hash = MessageDigest.getInstance("SHA-256"); hash.update("group_storage:group".getBytes(StandardCharsets.UTF_8)); hash.update((byte) 0);
      try (var s = connection.prepareStatement("SELECT pg_advisory_xact_lock(?)")) {
        s.setLong(1, ByteBuffer.wrap(hash.digest(id.toByteArray())).getLong()); s.execute();
      }
      var future = service.change(proof, UUID.randomUUID(), users.get(0), id, 0, new Announcements(false));
      awaitAdvisoryWait(); proof.revoked = true; connection.commit();
      assertThatThrownBy(future::join).hasRootCauseInstanceOf(SecurityException.class);
    }
    assertThat(current().getRevision()).isZero(); assertCounts(1, 1);
  }
  void awaitAdvisoryWait() throws Exception {
    long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
    while (System.nanoTime() < until) {
      try (var c = db.dataSource.getConnection(); var s = c.createStatement(); var r = s.executeQuery("SELECT count(*) FROM pg_locks WHERE database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND locktype='advisory' AND NOT granted")) {
        r.next(); if (r.getLong(1) > 0) return;
      }
      Thread.sleep(10);
    }
    throw new AssertionError("Operation did not reach PostgreSQL advisory lock wait");
  }
  @Test void executorExpiryNeverStartsSqlAndNewProofCannotExtendQueuedWork() throws Exception {
    var tasks = new ArrayDeque<Runnable>(); var queued = service(db.dataSource, tasks::add);
    var old = new Proof(acis.get(0), enrollments.get(0), 100);
    var future = queued.create(old, UUID.randomUUID(), users.get(0), creation);
    Thread.sleep(150); proof(0); tasks.remove().run(); reject(future, Failure.EXPIRED); assertEmpty();
  }
  @Test void futureDatedOrRevokedProofIsRejectedBeforeAnyWrite() throws Exception {
    reject(service.create(new Proof(acis.get(0), enrollments.get(0), 10_000), UUID.randomUUID(), users.get(0), creation), Failure.INVALID);
    var proof = proof(0); proof.revoked = true;
    assertThatThrownBy(() -> service.create(proof, UUID.randomUUID(), users.get(0), creation).join()).hasRootCauseInstanceOf(SecurityException.class); assertEmpty();
  }
  @Test void revocationAfterCommitSuppressesResultAndFreshProofCanRecoverExactResult() throws Exception {
    var request = UUID.randomUUID(); var proof = proof(0);
    var wrapped = connectionHook((method, raw) -> {
      if (method.equals("commit")) { raw.commit(); proof.revoked = true; return true; } return false;
    });
    assertThatThrownBy(() -> service(wrapped, executor).create(proof, request, users.get(0), creation).join()).hasRootCauseInstanceOf(SecurityException.class);
    assertCounts(1, 1); var replay = service.create(proof(0), request, users.get(0), creation).join(); assertThat(replay.getRevision()).isZero(); assertCounts(1, 1);
  }
  @Test void actorRevocationAfterOutboxInsertRollsBackAllWrites() throws Exception {
    var proof = proof(0);
    var source = statementHook("INSERT INTO group_storage.group_authority_outbox", () -> proof.revoked = true);
    assertThatThrownBy(() -> service(source, executor).create(proof, UUID.randomUUID(), users.get(0), creation).join())
        .hasRootCauseInstanceOf(SecurityException.class);
    assertEmpty();
  }
  @Test void targetRevocationAfterOutboxInsertRollsBackInvitationAndRevision() throws Exception {
    var initial = create(); var target = proof(1);
    var source = statementHook("INSERT INTO group_storage.group_authority_outbox", () -> target.revoked = true);
    assertThatThrownBy(() -> service(source, executor).change(proof(0), UUID.randomUUID(), users.get(0), id, 0,
        new Invite(target, principal(1))).join()).hasRootCauseInstanceOf(SecurityException.class);
    assertThat(current()).isEqualTo(initial); assertCounts(1, 1);
  }
  @ParameterizedTest @ValueSource(booleans = {false, true})
  void proofExpiryDuringSqlLockWaitIsBoundedAndWritesNothing(boolean targetExpires) throws Exception {
    create();
    try (var connection = db.dataSource.getConnection()) {
      connection.setAutoCommit(false);
      var hash = MessageDigest.getInstance("SHA-256"); hash.update("group_storage:group".getBytes(StandardCharsets.UTF_8)); hash.update((byte) 0);
      try (var s = connection.prepareStatement("SELECT pg_advisory_xact_lock(?)")) {
        s.setLong(1, ByteBuffer.wrap(hash.digest(id.toByteArray())).getLong()); s.execute();
      }
      var proof = new Proof(acis.get(0), enrollments.get(0), targetExpires ? 3900 : 300);
      Change command = targetExpires ? new Invite(new Proof(acis.get(1), enrollments.get(1), 300), principal(1)) : new Announcements(false);
      var future = service.change(proof, UUID.randomUUID(), users.get(0), id, 0, command);
      awaitAdvisoryWait();
      assertThatThrownBy(() -> future.get(2, TimeUnit.SECONDS)).hasRootCauseInstanceOf(java.sql.SQLException.class);
      connection.commit();
    }
    assertThat(current().getRevision()).isZero(); assertCounts(1, 1);
  }
  @Test void idempotencyKeyCannotBeReusedAcrossDifferentGroupNamespaces() throws Exception {
    var request = UUID.randomUUID(); service.create(proof(0), request, users.get(0), creation).join();
    var other = new SyntheticGroupFixture(2);
    var secondService = new GroupAuthority(db.dataSource, executor, other.server, config, Clock.systemUTC());
    var secondGroup = other.submitted.toBuilder().clearMembers().addMembers(other.submitted.getMembers(0)).build();
    reject(secondService.create(proof(0), request, other.authenticatedUser(0), secondGroup), Failure.CONFLICT);
    assertCounts(1, 1);
  }
  @Test void acceptanceReplayPreservesOriginalResultAndDoesNotDuplicatePromotion() throws Exception {
    create(); change(0, 0, invite(1)); var request = UUID.randomUUID();
    var command = new Accept(fixture.submitted.getMembers(1).getPresentation());
    var first = service.change(proof(1), request, users.get(1), id, 1, command).join();
    assertThat(service.change(proof(1), request, users.get(1), id, 1, command).join()).isEqualTo(first);
    assertCounts(3, 2);
  }
  @Test void committedTerminationCanBeAcknowledgedWithoutGrantingReadOrMutation() throws Exception {
    create(); var request = UUID.randomUUID(); var command = new Terminate();
    var state = service.change(proof(0), request, users.get(0), id, 0, command).join();
    reject(service.change(proof(0), request, users.get(0), id, 0, command), Failure.DENIED);
    reject(service.get(proof(0), users.get(0), id), Failure.DENIED);
    assertThat(service.outcome(proof(0), request).join()).contains(new CommittedOutcome(id, 1, state.getNativeSha256()));
    assertThat(service.outcome(proof(1), request).join()).isEmpty();
    reject(service.outcome(new Proof(acis.get(0), UUID.randomUUID(), 3900), request), Failure.DENIED);
    assertCounts(2, 1);
  }
  @Test void inviteeRevocationDuringCommitSuppressesResponseWithoutReissuingProof() throws Exception {
    create(); var request = UUID.randomUUID(); var target = proof(1);
    var wrapped = connectionHook((method, raw) -> {
      if (method.equals("commit")) { raw.commit(); target.revoked = true; return true; } return false;
    });
    assertThatThrownBy(() -> service(wrapped, executor).change(proof(0), request, users.get(0), id, 0,
        new Invite(target, principal(1))).join()).hasRootCauseInstanceOf(SecurityException.class);
    assertCounts(2, 2); assertThat(service.outcome(proof(0), request).join()).isPresent();
    reject(service.change(new Proof(acis.get(1), UUID.randomUUID(), 3900), UUID.randomUUID(), users.get(1), id, 1,
        new Accept(fixture.submitted.getMembers(1).getPresentation())), Failure.DENIED);
  }
  @Test void runtimeUsesNarrowGrantsAndCannotDeleteNamespaceOrRewriteOutbox() throws Exception {
    String role = "authority_runtime_" + UUID.randomUUID().toString().replace("-", "");
    sql("CREATE ROLE " + role + " NOLOGIN");
    try {
      sql("GRANT USAGE ON SCHEMA group_storage TO " + role);
      sql("GRANT SELECT,INSERT,UPDATE,DELETE ON group_storage.groups,group_storage.group_logs,group_storage.manifests,group_storage.items,group_storage.group_roster TO " + role);
      sql("GRANT SELECT,INSERT ON group_storage.group_namespaces,group_storage.group_authority_requests,group_storage.group_authority_outbox TO " + role);
      sql("GRANT SELECT,INSERT,UPDATE ON group_storage.group_authority TO " + role);
      var restricted = mock(DataSource.class);
      when(restricted.getConnection()).thenAnswer(ignored -> {
        var connection = db.dataSource.getConnection();
        try (var statement = connection.createStatement()) { statement.execute("SET ROLE " + role); }
        return connection;
      });
      var runtime = service(restricted, executor);
      runtime.create(proof(0), UUID.randomUUID(), users.get(0), creation).join();
      runtime.change(proof(0), UUID.randomUUID(), users.get(0), id, 0, invite(1)).join();
      runtime.change(proof(1), UUID.randomUUID(), users.get(1), id, 1, new Accept(fixture.submitted.getMembers(1).getPresentation())).join();
      assertThat(runtime.get(proof(0), users.get(0), id).join().getRevision()).isEqualTo(2); assertCounts(3, 2);
      try (var c = restricted.getConnection(); var statement = c.createStatement()) {
        assertThatThrownBy(() -> statement.executeUpdate("DELETE FROM group_storage.group_namespaces")).isInstanceOf(java.sql.SQLException.class);
        assertThatThrownBy(() -> statement.executeUpdate("UPDATE group_storage.group_authority_outbox SET revision=42")).isInstanceOf(java.sql.SQLException.class);
        assertThatThrownBy(() -> statement.executeUpdate("DELETE FROM group_storage.group_authority_requests")).isInstanceOf(java.sql.SQLException.class);
      }
    } finally { sql("DROP OWNED BY " + role); sql("DROP ROLE " + role); }
  }
  @Test void approvalEpochChangeWithSameEnrollmentRejectsOldInviteAndActiveMembership() throws Exception {
    var request = UUID.randomUUID(); service.create(proof(0), request, users.get(0), creation).join(); change(0, 0, invite(1));
    var newTargetEpoch = proof(1); newTargetEpoch.epoch = 2;
    reject(service.change(newTargetEpoch, UUID.randomUUID(), users.get(1), id, 1,
        new Accept(fixture.submitted.getMembers(1).getPresentation())), Failure.DENIED);
    var newActorEpoch = proof(0); newActorEpoch.epoch = 2;
    reject(service.get(newActorEpoch, users.get(0), id), Failure.DENIED);
    reject(service.create(newActorEpoch, request, users.get(0), creation), Failure.CONFLICT);
    reject(service.outcome(newActorEpoch, request), Failure.DENIED);
    assertCounts(2, 2);
  }
  @ParameterizedTest @ValueSource(longs = {-1, 9007199254740992L})
  void invalidApprovalEpochIsRejectedBeforeDatabaseWork(long epoch) throws Exception {
    var proof = proof(0); proof.epoch = epoch;
    reject(service.create(proof, UUID.randomUUID(), users.get(0), creation), Failure.INVALID); assertEmpty();
  }
  @Test void malformedReadIdentifiersNeverAcquireDatabaseConnection() {
    var unopened = mock(DataSource.class); var isolated = service(unopened, executor);
    reject(isolated.get(proof(0), users.get(0), null), Failure.INVALID);
    reject(isolated.get(proof(0), users.get(0), ByteString.EMPTY), Failure.INVALID);
    reject(isolated.get(proof(0), users.get(0), ByteString.copyFrom(new byte[31])), Failure.INVALID);
    reject(isolated.get(proof(0), users.get(0), ByteString.copyFrom(new byte[33])), Failure.INVALID);
    assertThatThrownBy(() -> isolated.outcome(proof(0), null).join()).hasRootCauseInstanceOf(NullPointerException.class);
    verifyNoInteractions(unopened);
  }
  DataSource statementHook(String prefix, Runnable afterExecute) throws Exception {
    var wrapped = mock(DataSource.class);
    when(wrapped.getConnection()).thenAnswer(ignored -> {
      var raw = db.dataSource.getConnection();
      return Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{Connection.class}, (proxy, method, args) -> {
        try {
          Object result = method.invoke(raw, args);
          if (method.getName().equals("prepareStatement") && ((String) args[0]).startsWith(prefix)) {
            var statement = (java.sql.PreparedStatement) result;
            return Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{java.sql.PreparedStatement.class}, (p, m, a) -> {
              try { Object value = m.invoke(statement, a); if (m.getName().equals("executeUpdate")) afterExecute.run(); return value; }
              catch (InvocationTargetException error) { throw error.getCause(); }
            });
          }
          return result;
        } catch (InvocationTargetException error) { throw error.getCause(); }
      });
    }); return wrapped;
  }
  @FunctionalInterface interface ConnectionHook { boolean handle(String method, Connection raw) throws Exception; }
  DataSource connectionHook(ConnectionHook hook) throws Exception {
    var wrapped = mock(DataSource.class);
    when(wrapped.getConnection()).thenAnswer(ignored -> {
      var raw = db.dataSource.getConnection();
      return Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{Connection.class}, (proxy, method, args) -> {
        if (hook.handle(method.getName(), raw)) return null;
        try { return method.invoke(raw, args); } catch (InvocationTargetException e) { throw e.getCause(); }
      });
    }); return wrapped;
  }
}
