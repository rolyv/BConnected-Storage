// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.controllers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.google.protobuf.ByteString;
import io.dropwizard.auth.basic.BasicCredentials;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.postgresql.ds.PGSimpleDataSource;
import org.signal.libsignal.protocol.ServiceId;
import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.protocol.ServiceId.Pni;
import org.signal.libsignal.zkgroup.NotarySignature;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.auth.ClientZkAuthOperations;
import org.signal.libsignal.zkgroup.auth.ServerZkAuthOperations;
import org.signal.libsignal.zkgroup.groups.ClientZkGroupCipher;
import org.signal.libsignal.zkgroup.groups.GroupSecretParams;
import org.signal.libsignal.zkgroup.groupsend.GroupSendDerivedKeyPair;
import org.signal.libsignal.zkgroup.groupsend.GroupSendEndorsementsResponse;
import org.signal.libsignal.zkgroup.profiles.ClientZkProfileOperations;
import org.signal.libsignal.zkgroup.profiles.ProfileKey;
import org.signal.libsignal.zkgroup.profiles.ServerZkProfileOperations;
import org.signal.storageservice.auth.ExternalGroupCredentialGenerator;
import org.signal.storageservice.auth.GroupUser;
import org.signal.storageservice.auth.GroupUserAuthenticator;
import org.signal.storageservice.configuration.GroupConfiguration;
import org.signal.storageservice.groups.GroupValidator;
import org.signal.storageservice.storage.GroupsManager;
import org.signal.storageservice.storage.PostgresStorage;
import org.signal.storageservice.storage.protos.groups.AccessControl;
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
  private PGSimpleDataSource operator;
  private PGSimpleDataSource dataSource;
  private String database;
  private ExecutorService executor;
  private PostgresStorage storage;
  private GroupsManager manager;

  @BeforeAll
  void createDisposableDatabase() throws Exception {
    String configuredUrl = System.getenv("BCONNECTED_GROUP_TEST_JDBC_URL");
    if (configuredUrl == null || !configuredUrl.startsWith("jdbc:postgresql://")) {
      throw new IllegalArgumentException("Capacity tests require an explicit loopback test database");
    }
    URI uri = URI.create(configuredUrl.substring("jdbc:".length()));
    if (!List.of("127.0.0.1", "localhost", "::1").contains(uri.getHost())
        || !uri.getPath().matches("/[a-zA-Z0-9_]+_test")
        || uri.getQuery() != null || uri.getUserInfo() != null || uri.getFragment() != null) {
      throw new IllegalArgumentException("Only a plain loopback database ending in _test is permitted");
    }
    operator = localDataSource(uri, uri.getPath().substring(1));
    database = "bconnected_capacity_" + UUID.randomUUID().toString().replace("-", "") + "_test";
    try (var connection = operator.getConnection(); var statement = connection.createStatement()) {
      statement.execute("CREATE DATABASE " + database);
    }
    dataSource = localDataSource(uri, database);
    try (var connection = dataSource.getConnection(); var statement = connection.createStatement()) {
      statement.execute(Files.readString(Path.of("bconnected/migrations/001-postgres.sql")));
    }
    executor = Executors.newFixedThreadPool(2);
    storage = new PostgresStorage(dataSource, executor);
    manager = new GroupsManager(storage);
  }

  private PGSimpleDataSource localDataSource(URI uri, String name) {
    var result = new PGSimpleDataSource();
    result.setServerNames(new String[] {uri.getHost()});
    result.setPortNumbers(new int[] {uri.getPort() < 0 ? 5432 : uri.getPort()});
    result.setDatabaseName(name);
    result.setUser("postgres");
    result.setPassword(System.getenv("BCONNECTED_TEST_POSTGRES_PASSWORD"));
    result.setConnectTimeout(5);
    result.setSocketTimeout(30);
    result.setOptions("-c statement_timeout=15000 -c lock_timeout=5000");
    return result;
  }

  @AfterAll
  void closeAndWriteMeasurements() throws Exception {
    try {
      if (executor != null) executor.close();
    } finally {
      if (operator != null && database != null) {
        try (var connection = operator.getConnection(); var statement = connection.createStatement()) {
          statement.execute("DROP DATABASE IF EXISTS " + database + " WITH (FORCE)");
        }
      }
    }
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
    long started = System.nanoTime();
    var server = ServerSecretParams.generate();
    var groupSecret = GroupSecretParams.generate();
    var cipher = new ClientZkGroupCipher(groupSecret);
    Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    Instant redemption = now.truncatedTo(ChronoUnit.DAYS);
    var clock = Clock.fixed(now, ZoneOffset.UTC);
    var clientProfiles = new ClientZkProfileOperations(server.getPublicParams());
    var serverProfiles = new ServerZkProfileOperations(server);
    var random = new SecureRandom();
    var identities = new ArrayList<ServiceId>();
    var request = Group.newBuilder()
        .setPublicKey(ByteString.copyFrom(groupSecret.getPublicParams().serialize()))
        .setTitle(encryptedTitle(cipher, "Synthetic alumni announcements"))
        .setAnnouncementsOnly(true)
        .setAccessControl(AccessControl.newBuilder()
            .setMembers(AccessControl.AccessRequired.ADMINISTRATOR)
            .setAttributes(AccessControl.AccessRequired.ADMINISTRATOR)
            .setAddFromInviteLink(AccessControl.AccessRequired.UNSATISFIABLE));
    for (int index = 0; index < count; index++) {
      var aci = new Aci(UUID.randomUUID());
      identities.add(aci);
      byte[] profileBytes = new byte[32];
      random.nextBytes(profileBytes);
      var key = new ProfileKey(profileBytes);
      var context = clientProfiles.createProfileKeyCredentialRequestContext(aci, key);
      var issued = serverProfiles.issueExpiringProfileKeyCredential(context.getRequest(), aci,
          key.getCommitment(aci), redemption.plus(2, ChronoUnit.DAYS));
      var credential = clientProfiles.receiveExpiringProfileKeyCredential(context, issued, now);
      var presentation = clientProfiles.createProfileKeyCredentialPresentation(groupSecret, credential);
      request.addMembers(Member.newBuilder()
          .setRole(index == 0 ? Member.Role.ADMINISTRATOR : Member.Role.DEFAULT)
          .setPresentation(ByteString.copyFrom(presentation.serialize())));
    }
    result.put("fixtureGenerationMs", elapsed(started));
    var admin = authenticatedUser((Aci) identities.getFirst(), groupSecret, server, redemption);
    var member = authenticatedUser((Aci) identities.get(1), groupSecret, server, redemption);
    var controller = new GroupsController(clock, manager, server, null, null, CONFIG,
        new ExternalGroupCredentialGenerator(new byte[32], clock));
    Group submitted = Group.parseFrom(request.build().toByteArray());
    result.put("createRequestBytes", submitted.getSerializedSize());

    started = System.nanoTime();
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
    verifyEndorsements(created, identities, groupSecret, server, now);
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
    verifyEndorsements(GroupResponse.newBuilder().setGroup(finalGroup)
        .setGroupSendEndorsementsResponse(restored.getGroupSendEndorsementsResponse()).build(),
        identities, groupSecret, server, now);
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

  private GroupUser authenticatedUser(Aci aci, GroupSecretParams group, ServerSecretParams server,
      Instant redemption) throws Exception {
    var pni = new Pni(UUID.randomUUID());
    var issued = new ServerZkAuthOperations(server).issueAuthCredentialWithPniZkc(aci, pni, redemption);
    var client = new ClientZkAuthOperations(server.getPublicParams());
    var credential = client.receiveAuthCredentialWithPniAsServiceId(aci, pni, redemption.getEpochSecond(), issued);
    var presentation = client.createAuthCredentialPresentation(group, credential);
    return new GroupUserAuthenticator(new ServerZkAuthOperations(server)).authenticate(new BasicCredentials(
        HexFormat.of().formatHex(group.getPublicParams().serialize()),
        HexFormat.of().formatHex(presentation.serialize()))).orElseThrow();
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

  private static void verifyEndorsements(GroupResponse group, List<ServiceId> identities,
      GroupSecretParams secret, ServerSecretParams server, Instant now) throws Exception {
    var response = new GroupSendEndorsementsResponse(group.getGroupSendEndorsementsResponse().toByteArray());
    var endorsements = response.receive(identities, (Aci) identities.getFirst(), now, secret, server.getPublicParams());
    var token = endorsements.combinedEndorsement().toFullToken(secret, response.getExpiration());
    token.verify(identities.subList(1, identities.size()), now,
        GroupSendDerivedKeyPair.forExpiration(response.getExpiration(), server));
  }

  private static long elapsed(long start) { return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start); }
}
