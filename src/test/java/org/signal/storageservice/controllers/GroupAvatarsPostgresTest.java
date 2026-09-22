// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.controllers;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.auth.basic.BasicCredentialAuthFilter;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import java.time.Clock;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.signal.libsignal.zkgroup.auth.ServerZkAuthOperations;
import org.signal.storageservice.avatars.*;
import org.signal.storageservice.auth.*;
import org.signal.storageservice.configuration.GroupConfiguration;
import org.signal.storageservice.providers.*;
import org.signal.storageservice.storage.protos.groups.*;
import org.signal.storageservice.util.SystemMapper;

@EnabledIfEnvironmentVariable(named = "BCONNECTED_GROUP_TEST_JDBC_URL", matches = ".+")
@ExtendWith(DropwizardExtensionsSupport.class)
class GroupAvatarsPostgresTest {
  static final String OBJECT = "AAAAAAAAAAAAAAAAAAAAAA";
  final DisposableGroupDatabase database;
  final SyntheticGroupFixture fixture;
  final GroupAvatarStorage objects = mock(GroupAvatarStorage.class);
  final GroupAvatarService avatars;
  final GroupsController controller;
  final GroupUser admin;
  final ResourceExtension resources;
  Group group;
  Runnable duringSign = () -> {};
  Executor worker = Runnable::run;

  GroupAvatarsPostgresTest() throws Exception {
    database = new DisposableGroupDatabase(); fixture = new SyntheticGroupFixture(3); admin = fixture.authenticatedUser(0);
    avatars = new GroupAvatarService(objects, database.manager, task -> worker.execute(task), Clock.systemUTC());
    var configuration = new GroupConfiguration(10000, 1024, 8192, new byte[32], null, null);
    var external = new ExternalGroupCredentialGenerator(new byte[32], Clock.systemUTC());
    controller = new GroupsController(Clock.systemUTC(), database.manager, fixture.server, configuration, external, avatars);
    resources = ResourceExtension.builder()
        .setTestContainerFactory(new org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory())
        .addProvider(new AuthDynamicFeature(new BasicCredentialAuthFilter.Builder<GroupUser>()
        .setAuthenticator(new GroupUserAuthenticator(new ServerZkAuthOperations(fixture.server))).buildAuthFilter()))
        .addProvider(new AuthValueFactoryProvider.Binder<>(GroupUser.class)).addProvider(new ProtocolBufferMessageBodyProvider())
        .addProvider(new CompletionExceptionMapper()).setMapper(SystemMapper.getMapper())
        .addResource(controller).addResource(new GroupsV1Controller(Clock.systemUTC(), database.manager, fixture.server, configuration, external, avatars)).build();
  }
  @BeforeEach void seed() {
    var submitted = fixture.submitted.toBuilder().removeMembers(2).setAvatarUrl(GroupAvatarStorage.key(admin.getGroupId(), OBJECT)).build();
    group = ((GroupResponse) controller.createGroup(admin, submitted).join().getEntity()).getGroup();
    when(objects.upload(any())).thenAnswer(call -> { duringSign.run(); return upload(); });
    when(objects.download(any(), any())).thenAnswer(call -> { duringSign.run(); return download(); });
  }
  @AfterEach void cleanup() throws Exception { database.close(); }
  AvatarUploadAttributes upload() { return AvatarUploadAttributes.newBuilder().setKey(GroupAvatarStorage.key(admin.getGroupId(), OBJECT))
      .setAlgorithm("GOOG4-RSA-SHA256").setExpiresAt(Clock.systemUTC().instant().getEpochSecond() + 300).build(); }
  AvatarDownloadAttributes download() { return AvatarDownloadAttributes.newBuilder().setUrl("https://storage.googleapis.com/synthetic/object?generation=1")
      .setExpiresAt(Clock.systemUTC().instant().getEpochSecond() + 300).setContentLength(32).build(); }
  void change(java.util.function.UnaryOperator<Group.Builder> update) {
    group = update.apply(group.toBuilder().setVersion(group.getVersion() + 1)).build();
    assertThat(database.manager.updateGroup(admin.getGroupId(), group).join()).isEmpty();
  }
  jakarta.ws.rs.core.Response request(String path, int user) throws Exception {
    var request = resources.target(path).request(ProtocolBufferMediaType.APPLICATION_PROTOBUF);
    if (user >= 0) request.header("Authorization", fixture.authorization(user));
    return request.get();
  }
  int status(CompletableFuture<?> future) {
    try { future.join(); throw new AssertionError("Expected rejection"); }
    catch (CompletionException failure) { return ((jakarta.ws.rs.WebApplicationException) failure.getCause()).getResponse().getStatus(); }
  }
  @Test void realZkHttpAdminUploadMemberDownloadAndUnauthorizedDenials() throws Exception {
    try (var response = request("/v2/groups/avatar/form", 0)) {
      assertThat(response.getStatus()).isEqualTo(200);
      assertThat(response.getHeaderString("Cache-Control")).isEqualTo("no-store");
      assertThat(AvatarUploadAttributes.parseFrom(response.readEntity(byte[].class)).getKey()).isEqualTo(upload().getKey());
    }
    assertThat(request("/v1/groups/avatar/form", 0).getStatus()).isEqualTo(200);
    assertThat(request("/v2/groups/avatar/form", 1).getStatus()).isEqualTo(403);
    assertThat(request("/v2/groups/avatar/" + OBJECT, 1).getStatus()).isEqualTo(200);
    assertThat(request("/v2/groups/avatar/" + OBJECT, 2).getStatus()).isEqualTo(403);
    assertThat(request("/v2/groups/avatar/" + OBJECT, -1).getStatus()).isEqualTo(401);
    assertThat(request("/v2/groups/avatar/form", -1).getStatus()).isEqualTo(401);
  }
  @Test void preCreationUploadPreservesGroupCreationFlow() throws Exception {
    try (var c = database.dataSource.getConnection(); var s = c.prepareStatement("DELETE FROM group_storage.groups WHERE group_id=?")) {
      s.setBytes(1, admin.getGroupId().toByteArray()); s.executeUpdate();
    }
    assertThat(controller.getAvatarUploadForm(admin).join().getStatus()).isEqualTo(200);
  }
  @Test void terminatedGroupKeepsReadButRejectsUpload() {
    change(builder -> builder.setTerminated(true));
    assertThat(status(avatars.upload(admin))).isEqualTo(423);
    assertThat(avatars.download(admin, OBJECT, null).join().getStatus()).isEqualTo(200);
  }
  @Test void removalWhileSigningSuppressesCapability() {
    duringSign = () -> change(builder -> builder.removeMembers(0));
    assertThat(status(avatars.upload(admin))).isEqualTo(403);
    verify(objects).upload(admin.getGroupId());
  }
  @Test void permissionsChangedDuringSigningSuppressUpload() {
    change(builder -> builder.setAccessControl(group.getAccessControl().toBuilder().setAttributes(AccessControl.AccessRequired.MEMBER)));
    duringSign = () -> change(builder -> builder.setAccessControl(group.getAccessControl().toBuilder().setAttributes(AccessControl.AccessRequired.ADMINISTRATOR)));
    assertThat(status(avatars.upload(user(1)))).isEqualTo(403);
  }
  GroupUser user(int index) { try { return fixture.authenticatedUser(index); } catch (Exception failure) { throw new AssertionError(failure); } }
  @Test void validInviteAllowsOnlyCurrentAvatarAndRespectsPasswordRotation() {
    byte[] password = new byte[16]; java.util.Arrays.fill(password, (byte) 1);
    change(builder -> builder.setInviteLinkPassword(com.google.protobuf.ByteString.copyFrom(password))
        .setAccessControl(group.getAccessControl().toBuilder().setAddFromInviteLink(AccessControl.AccessRequired.ANY)));
    var link = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(password);
    assertThat(avatars.download(user(2), OBJECT, link).join().getStatus()).isEqualTo(200);
    assertThat(status(avatars.download(user(2), "AAAAAAAAAAAAAAAAAAAAAQ", link))).isEqualTo(403);
    duringSign = () -> change(builder -> builder.clearInviteLinkPassword());
    assertThat(status(avatars.download(user(2), OBJECT, link))).isEqualTo(403);
  }
  @Test void pendingMemberCanReadButCannotUpload() {
    var member = group.getMembers(1);
    change(builder -> builder.removeMembers(1).addMembersPendingProfileKey(MemberPendingProfileKey.newBuilder().setMember(member)));
    assertThat(avatars.download(user(1), OBJECT, null).join().getStatus()).isEqualTo(200);
    assertThat(status(avatars.upload(user(1)))).isEqualTo(403);
  }
  @Test void pendingApprovalCanPreviewCurrentAvatarButBannedAndTerminatedCannot() {
    var outsider = user(2);
    var ciphertext = com.google.protobuf.ByteString.copyFrom(fixture.cipher.encrypt(fixture.identities.get(2)).serialize());
    change(builder -> builder.addMembersPendingAdminApproval(MemberPendingAdminApproval.newBuilder().setUserId(ciphertext)));
    assertThat(avatars.download(outsider, OBJECT, null).join().getStatus()).isEqualTo(200);
    assertThat(status(avatars.download(outsider, "AAAAAAAAAAAAAAAAAAAAAQ", null))).isEqualTo(403);
    change(builder -> builder.setTerminated(true));
    assertThat(status(avatars.download(outsider, OBJECT, null))).isEqualTo(423);
    change(builder -> builder.setTerminated(false).addMembersBanned(MemberBanned.newBuilder().setUserId(ciphertext)));
    assertThat(status(avatars.download(outsider, OBJECT, null))).isEqualTo(403);
  }
  @Test void emptyOrMalformedInviteCannotEnablePreviewWithoutAStoredPassword() {
    change(builder -> builder.clearInviteLinkPassword()
        .setAccessControl(group.getAccessControl().toBuilder().setAddFromInviteLink(AccessControl.AccessRequired.ANY)));
    for (String password : new String[] {null, "", "==", "a"})
      assertThat(status(avatars.download(user(2), OBJECT, password))).isEqualTo(403);
    verifyNoInteractions(objects);
  }
  @Test void providerFailuresAndWorkerSaturationReturnUnavailableWithoutProviderDetails() {
    when(objects.upload(any())).thenThrow(new RuntimeException("secret signed URL must not escape"));
    assertThat(status(avatars.upload(admin))).isEqualTo(503);
    worker = task -> { throw new java.util.concurrent.RejectedExecutionException(); };
    assertThat(status(avatars.upload(admin))).isEqualTo(503);
  }
  @Test void expiredCapabilityCannotEscapeAfterSigningWait() {
    when(objects.upload(any())).thenReturn(upload().toBuilder().setExpiresAt(1).build());
    assertThat(status(avatars.upload(admin))).isEqualTo(503);
  }
  @Test void missingObjectMapsToNotFoundButGroupAuthorizationComesFirst() {
    when(objects.download(any(), any())).thenThrow(new jakarta.ws.rs.NotFoundException());
    assertThat(status(avatars.download(admin, OBJECT, null))).isEqualTo(404);
    clearInvocations(objects);
    assertThat(status(avatars.download(user(2), OBJECT, null))).isEqualTo(403);
    verifyNoInteractions(objects);
  }
  @Test void canonicalGroupKeyCannotBeRebound() {
    assertThatThrownBy(() -> avatars.download(admin, "AAAAAAAAAAAAAAAAAAAAAB", null)).isInstanceOf(jakarta.ws.rs.BadRequestException.class);
    verifyNoInteractions(objects);
  }
}
