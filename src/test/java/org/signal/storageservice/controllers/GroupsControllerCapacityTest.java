// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.controllers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.google.protobuf.ByteString;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.core.Response;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.signal.libsignal.zkgroup.NotarySignature;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.groups.ClientZkGroupCipher;
import org.signal.libsignal.zkgroup.profiles.ServerZkProfileOperations;
import org.signal.storageservice.auth.ExternalGroupCredentialGenerator;
import org.signal.storageservice.configuration.GroupConfiguration;
import org.signal.storageservice.groups.GroupValidator;
import org.signal.storageservice.storage.GroupsManager;
import org.signal.storageservice.storage.PostgresStorage;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupAttributeBlob;
import org.signal.storageservice.storage.protos.groups.GroupChange;
import org.signal.storageservice.storage.protos.groups.GroupChangeResponse;
import org.signal.storageservice.storage.protos.groups.GroupResponse;
import org.signal.storageservice.storage.protos.groups.Member;
import org.signal.storageservice.util.SystemMapper;

/**
 * Opt-in, single-process controller/cryptography/storage characterization. No HTTP transport,
 * Signal accounts, messages, provider calls, production database, or throughput claim.
 */
@EnabledIfEnvironmentVariable(named = "BCONNECTED_GROUP_CAPACITY", matches = "true")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Timeout(value = 15, unit = TimeUnit.MINUTES)
class GroupsControllerCapacityTest {
  private static final int CAP = 10_000;
  private static final GroupConfiguration CONFIG =
      new GroupConfiguration(CAP, 1024, 8192, new byte[32], null, null);
  private final List<Map<String, Object>> measurements = new ArrayList<>();
  private DisposableGroupDatabase database;
  private PostgresStorage storage;
  private GroupsManager manager;

  @BeforeAll
  void createDisposableDatabase() throws Exception {
    database = new DisposableGroupDatabase();
    storage = database.storage;
    manager = database.manager;
  }

  @AfterAll
  void closeAndWriteMeasurements() throws Exception {
    if (database != null) database.close();
    measurements.sort(java.util.Comparator.comparingInt(row -> ((Number) row.get("members")).intValue()));
    var evidence = new LinkedHashMap<String, Object>();
    evidence.put("recordedAt", Instant.now().toString());
    evidence.put("scope", "synthetic libsignal controller and disposable local PostgreSQL only");
    evidence.put("javaVersion", System.getProperty("java.version"));
    evidence.put("logicalProcessors", Runtime.getRuntime().availableProcessors());
    evidence.put("maxHeapBytes", Runtime.getRuntime().maxMemory());
    evidence.put("configuredMemberCap", CAP);
    evidence.put("httpTransportTested", false);
    evidence.put("messageDeliveryTested", false);
    evidence.put("announcementSendAuthorizationTested", false);
    evidence.put("realAccountsCreated", 0);
    evidence.put("measurements", measurements);
    Files.writeString(Path.of("target/group-capacity-evidence.json"),
        SystemMapper.getMapper().writerWithDefaultPrettyPrinter().writeValueAsString(evidence));
  }

  @ParameterizedTest(name = "{0} distinct synthetic encrypted members")
  @ValueSource(ints = {50, 500, 2000, 8000})
  void signedControllerFlowAtPilotSizes(int count) throws Exception {
    var result = new LinkedHashMap<String, Object>();
    result.put("members", count);
    var fixture = new SyntheticGroupFixture(count);
    var server = fixture.server;
    var cipher = fixture.cipher;
    var clock = Clock.fixed(fixture.now, ZoneOffset.UTC);
    result.put("fixtureGenerationMs", fixture.generationMs);
    var admin = fixture.authenticatedUser(0);
    var member = fixture.authenticatedUser(1);
    var controller = new GroupsController(clock, manager, server, CONFIG,
        new ExternalGroupCredentialGenerator(new byte[32], clock));
    Group submitted = fixture.submitted;
    result.put("createRequestBytes", submitted.getSerializedSize());

    long started = System.nanoTime();
    GroupResponse created = successful(controller.createGroup(admin, submitted), GroupResponse.class);
    result.put("createControllerAndSqlMs", elapsed(started));
    result.put("persistedGroupBytes", created.getGroup().getSerializedSize());
    result.put("createResponseBytes", created.getSerializedSize());
    result.put("endorsementBytes", created.getGroupSendEndorsementsResponse().size());
    assertThat(created.getGroup().getMembersCount()).isEqualTo(count);
    assertThat(created.getGroup().getMembersList()).extracting(Member::getUserId).doesNotHaveDuplicates();
    assertThat(created.getGroup().getMembersList()).allMatch(m -> m.getPresentation().isEmpty());
    assertThat(created.getGroup().getAnnouncementsOnly()).isTrue();
    assertThat(created.getGroup().getMembersList()).filteredOn(m -> m.getRole() == Member.Role.ADMINISTRATOR)
        .hasSize(1);
    assertThat(storage.getGroup(admin.getGroupId()).join()).contains(created.getGroup());
    started = System.nanoTime();
    fixture.verifyEndorsements(created);
    result.put("clientEndorsementVerificationMs", elapsed(started));

    started = System.nanoTime();
    GroupResponse fetched = successful(controller.getGroup(member), GroupResponse.class);
    result.put("memberReadControllerAndSqlMs", elapsed(started));
    assertThat(fetched.getGroup()).isEqualTo(created.getGroup());
    // Upstream grants group-send endorsements to ordinary members too. This does not enforce
    // announcement MESSAGE sending; that separate client/server boundary remains unproven.
    assertThat(fetched.getGroupSendEndorsementsResponse()).isNotEmpty();
    var disableAnnouncements = GroupChange.Actions.newBuilder().setVersion(1)
        .setModifyAnnouncementsOnly(GroupChange.Actions.ModifyAnnouncementsOnlyAction.newBuilder()
            .setAnnouncementsOnly(false)).build();
    assertForbidden(controller.modifyGroup(member, "BConnected capacity fixture", null, disableAnnouncements));
    var promoteSelf = GroupChange.Actions.newBuilder().setVersion(1)
        .addModifyMemberRoles(GroupChange.Actions.ModifyMemberRoleAction.newBuilder()
            .setUserId(created.getGroup().getMembers(1).getUserId()).setRole(Member.Role.ADMINISTRATOR)).build();
    assertForbidden(controller.modifyGroup(member, "BConnected capacity fixture", null, promoteSelf));
    assertThat(storage.getGroup(admin.getGroupId()).join()).contains(created.getGroup());

    var title = encryptedTitle(cipher, "Updated synthetic announcements");
    var edit = GroupChange.Actions.newBuilder().setVersion(1)
        .setModifyTitle(GroupChange.Actions.ModifyTitleAction.newBuilder().setTitle(title)).build();
    assertForbidden(controller.modifyGroup(member, "BConnected capacity fixture", null, edit));
    started = System.nanoTime();
    GroupChangeResponse modified = successful(
        controller.modifyGroup(admin, "BConnected capacity fixture", null, edit), GroupChangeResponse.class);
    result.put("adminSignedUpdateControllerAndSqlMs", elapsed(started));
    verifySignature(modified.getGroupChange(), server);
    var updated = storage.getGroup(admin.getGroupId()).join().orElseThrow();
    assertThat(updated.getVersion()).isEqualTo(1);
    assertThat(updated.getMembersCount()).isEqualTo(count);
    assertThat(updated.getAnnouncementsOnly()).isTrue();
    assertThat(GroupAttributeBlob.parseFrom(cipher.decryptBlob(updated.getTitle().toByteArray())).getTitle())
        .isEqualTo("Updated synthetic announcements");
    try (Response stale = controller.modifyGroup(admin, "BConnected capacity fixture", null, edit).join()) {
      assertThat(stale.getStatus()).isEqualTo(409);
    }

    // Two independently submitted writes for version 2 must have one winner and one signed log.
    var competing = List.of(
        edit.toBuilder().setVersion(2).setModifyTitle(GroupChange.Actions.ModifyTitleAction.newBuilder()
            .setTitle(encryptedTitle(cipher, "Concurrent A"))).build(),
        edit.toBuilder().setVersion(2).setModifyTitle(GroupChange.Actions.ModifyTitleAction.newBuilder()
            .setTitle(encryptedTitle(cipher, "Concurrent B"))).build());
    started = System.nanoTime();
    var first = controller.modifyGroup(admin, "BConnected capacity fixture", null, competing.get(0));
    var second = controller.modifyGroup(admin, "BConnected capacity fixture", null, competing.get(1));
    try (Response a = first.join(); Response b = second.join()) {
      assertThat(List.of(a.getStatus(), b.getStatus())).containsExactlyInAnyOrder(200, 409);
      verifySignature(((GroupChangeResponse) (a.getStatus() == 200 ? a : b).getEntity()).getGroupChange(), server);
    }
    result.put("twoWriterConflictMs", elapsed(started));
    var remove = GroupChange.Actions.newBuilder().setVersion(3)
        .addDeleteMembers(GroupChange.Actions.DeleteMemberAction.newBuilder()
            .setDeletedUserId(created.getGroup().getMembers(count - 1).getUserId())).build();
    assertForbidden(controller.modifyGroup(member, "BConnected capacity fixture", null, remove));
    started = System.nanoTime();
    var removed = successful(controller.modifyGroup(admin, "BConnected capacity fixture", null, remove),
        GroupChangeResponse.class);
    verifySignature(removed.getGroupChange(), server);
    assertThat(storage.getGroup(admin.getGroupId()).join().orElseThrow().getMembersCount()).isEqualTo(count - 1);
    var restore = GroupChange.Actions.newBuilder().setVersion(4)
        .addAddMembers(GroupChange.Actions.AddMemberAction.newBuilder().setAdded(submitted.getMembers(count - 1)))
        .build();
    assertForbidden(controller.modifyGroup(member, "BConnected capacity fixture", null, restore));
    var restored = successful(controller.modifyGroup(admin, "BConnected capacity fixture", null, restore),
        GroupChangeResponse.class);
    verifySignature(restored.getGroupChange(), server);
    result.put("adminRemoveAndReAddControllerAndSqlMs", elapsed(started));
    var finalGroup = storage.getGroup(admin.getGroupId()).join().orElseThrow();
    assertThat(finalGroup.getMembersCount()).isEqualTo(count);
    assertThat(finalGroup.getMembersList()).extracting(Member::getUserId)
        .containsExactlyElementsOf(created.getGroup().getMembersList().stream().map(Member::getUserId).toList());
    fixture.verifyEndorsements(GroupResponse.newBuilder().setGroup(finalGroup)
        .setGroupSendEndorsementsResponse(restored.getGroupSendEndorsementsResponse()).build());
    var history = manager.getChangeRecords(admin.getGroupId(), finalGroup, 7, true, true, 0, 5).join();
    assertThat(history).hasSize(5);
    assertThat(history.getLast().getGroupState()).isEqualTo(finalGroup);
    for (int version = 1; version <= 4; version++) verifySignature(history.get(version).getGroupChange(), server);
    assertThat(finalGroup.getVersion()).isEqualTo(4);
    assertThat(finalGroup.getAnnouncementsOnly()).isTrue();
    result.put("signedHistoryRecordsVerified", 4);
    result.put("ordinaryMemberSettingsAndPromotionDenied", true);
    result.put("ordinaryMemberMembershipChangeDenied", true);
    result.put("adminRemoveAndReAddPassed", true);
    result.put("optimisticConflictPreserved", true);
    result.put("passed", true);
    measurements.add(result);
  }

  @Test
  void structuralCountAboveTenThousandRemainsRejected() {
    var builder = Group.newBuilder().setTitle(ByteString.copyFromUtf8("structural fixture"));
    // Deliberately only a count boundary test, not cryptographic fixtures or user accounts.
    for (int index = 0; index <= CAP; index++) builder.addMembers(Member.getDefaultInstance());
    var validator = new GroupValidator(new ServerZkProfileOperations(ServerSecretParams.generate()), CONFIG);
    assertThatThrownBy(() -> validator.validateFinalGroupState(builder.build()))
        .isInstanceOf(BadRequestException.class).hasMessage("group size cannot exceed " + CAP);
  }

  private static ByteString encryptedTitle(ClientZkGroupCipher cipher, String title) throws Exception {
    return ByteString.copyFrom(cipher.encryptBlob(GroupAttributeBlob.newBuilder().setTitle(title).build().toByteArray()));
  }

  private static <T> T successful(CompletableFuture<Response> future, Class<T> expected) {
    try (Response response = future.join()) {
      assertThat(response.getStatus()).isEqualTo(200);
      return expected.cast(response.getEntity());
    }
  }

  private static void assertForbidden(CompletableFuture<Response> future) {
    assertThatThrownBy(future::join).isInstanceOf(CompletionException.class).hasCauseInstanceOf(ForbiddenException.class);
  }

  private static void verifySignature(GroupChange change, ServerSecretParams server) throws Exception {
    assertThat(change.getServerSignature()).isNotEmpty();
    server.getPublicParams().verifySignature(change.getActions().toByteArray(),
        new NotarySignature(change.getServerSignature().toByteArray()));
  }

  private static long elapsed(long start) { return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start); }
}
