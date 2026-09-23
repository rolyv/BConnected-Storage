// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.controllers;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.ByteString;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.zkgroup.auth.ServerZkAuthOperations;
import org.signal.storageservice.configuration.GroupConfiguration;
import org.signal.storageservice.groups.bridge.*;
import org.signal.storageservice.groups.bridge.GroupBridgeProtocol.*;
import org.signal.storageservice.groups.manifests.*;
import org.signal.storageservice.storage.GroupAuthority;

/** Real native ZK proofs, PostgreSQL authority and Ed25519 manifests; callback transport is synthetic. */
@EnabledIfEnvironmentVariable(named = "BCONNECTED_GROUP_TEST_JDBC_URL", matches = ".+")
class GroupGatewayPostgresTest {
  final DisposableGroupDatabase db = new DisposableGroupDatabase();
  final SyntheticGroupFixture nativeFixture = new SyntheticGroupFixture(2);
  final javax.sql.DataSource dataSource = spy(db.dataSource);
  final java.util.concurrent.ExecutorService sql = Executors.newFixedThreadPool(4);
  final GroupAuthority authority = new GroupAuthority(dataSource, sql, nativeFixture.server,
      new GroupConfiguration(8000, 1024, 8192, new byte[32], null, null), Clock.systemUTC());
  final com.nimbusds.jose.jwk.OctetKeyPair key = GroupManifestCodecTest.key("gateway-test");
  final GroupManifestCodec codec = new GroupManifestCodec(Map.of(key.getKeyID(), new GroupManifestCodec.TrustedKey(key.toPublicJWK(), true)));
  final GroupManifestService manifests = new GroupManifestService(authority, codec, key);
  final ObjectMapper json = new ObjectMapper();
  final String binary = GroupBridgeProtocol.encode(new byte[32]);
  final String id = GroupBridgeProtocol.encode(nativeFixture.groupSecret.getPublicParams().getGroupIdentifier().serialize());
  final String root = "/v1/bconnected/groups";
  final AtomicInteger calls = new AtomicInteger();
  volatile Membership membership = new Membership(UUID.randomUUID(), 1, UUID.randomUUID(), binary, ((Aci) nativeFixture.identities.getFirst()).getRawUUID());
  volatile Operation expected;
  volatile CountDownLatch entered, release;
  volatile long remaining = 3_900_000_000L;
  final GroupAuthorizationResolver resolver = new GroupAuthorizationResolver(this::resolve, _ -> {}, 2, 4);
  final GroupGateway gateway = new GroupGateway(resolver, authority, manifests, new ServerZkAuthOperations(nativeFixture.server));
  GroupGatewayPostgresTest() throws Exception {}
  @AfterEach void cleanup() throws Exception { if (release != null) release.countDown(); resolver.close(); manifests.close(); sql.close(); db.close(); }
  byte[] resolve(byte[] bytes, long deadline) throws Exception {
    calls.incrementAndGet(); var r = GroupBridgeProtocol.request(bytes);
    if (!r.operation().equals(expected)) throw new SecurityException("Synthetic original binding mismatch");
    if (entered != null) entered.countDown(); if (release != null) release.await(3, TimeUnit.SECONDS);
    return GroupBridgeProtocol.encode(new Resolution(r.nonce(), r.operation(), membership, 1, remaining));
  }
  com.fasterxml.jackson.databind.node.ObjectNode nativeRequest(UUID request, boolean state) throws Exception {
    String nativeAuth = new String(Base64.getDecoder().decode(nativeFixture.authorization(0).substring(6)), StandardCharsets.US_ASCII);
    String[] parts = nativeAuth.split(":");
    return json.createObjectNode().put(state ? "requestNonce" : "requestId", request.toString())
        .put("groupPublicParams", GroupBridgeProtocol.encode(HexFormat.of().parseHex(parts[0])))
        .put("groupAuthPresentation", GroupBridgeProtocol.encode(HexFormat.of().parseHex(parts[1])));
  }
  byte[] createBody(UUID request) throws Exception {
    return json.writeValueAsBytes(nativeRequest(request, false).put("nativeGroup", GroupBridgeProtocol.encode(nativeFixture.submitted.toBuilder()
        .clearMembers().addMembers(nativeFixture.submitted.getMembers(0)).build().toByteArray())));
  }
  CompletableFuture<GroupGateway.Result> execute(String path, Kind kind, UUID request, byte[] body) {
    expected = new Operation(kind == Kind.OUTCOME ? "GET" : "POST", kind, kind == Kind.OUTCOME ? "" : id, request, GroupBridgeProtocol.digest(body));
    return gateway.execute(expected.method(), path, kind == Kind.OUTCOME ? null : "application/json", null, body, binary);
  }
  GroupGateway.Result create() throws Exception { var id = UUID.randomUUID(); return execute(root, Kind.CREATE, id, createBody(id)).join(); }
  @Test void createCurrentAnnouncementsTerminateAndRecoverMinimalOutcome() throws Exception {
    var created = (GroupGateway.Committed) create(); assertThat(created.outcome().revision()).isZero();
    var nonce = UUID.randomUUID();
    var current = (GroupGateway.Current) execute(root + "/" + id + "/state", Kind.STATE, nonce, json.writeValueAsBytes(nativeRequest(nonce, true))).join();
    assertThat(current.requestNonce()).isEqualTo(nonce);
    var verified = codec.verify(current.envelope(), ByteString.copyFrom(GroupBridgeProtocol.binary(id, 32)), GroupManifestCodec.KnownState.none(), GroupManifestCodec.Purpose.CURRENT_RESPONSE);
    assertThat(verified.roster()).singleElement().satisfies(e -> assertThat(e.aci()).isEqualTo(membership.aci()));
    var request = UUID.randomUUID();
    byte[] announcement = json.writeValueAsBytes(nativeRequest(request, false).put("kind", "ANNOUNCEMENTS").put("expectedRevision", 0).put("enabled", false));
    var changed = (GroupGateway.Committed) execute(root + "/" + id + "/changes", Kind.ANNOUNCEMENTS, request, announcement).join();
    assertThat(changed.outcome().revision()).isEqualTo(1);
    var end = UUID.randomUUID(); byte[] termination = json.writeValueAsBytes(nativeRequest(end, false).put("kind", "TERMINATE").put("expectedRevision", 1));
    assertThat(((GroupGateway.Committed) execute(root + "/" + id + "/changes", Kind.TERMINATE, end, termination).join()).outcome().revision()).isEqualTo(2);
    var outcome = (GroupGateway.Outcome) execute("/v1/bconnected/group-operations/" + end, Kind.OUTCOME, end, new byte[0]).join();
    assertThat(outcome.outcome()).isPresent().get().satisfies(o -> assertThat(o.revision()).isEqualTo(2));
    assertThatThrownBy(() -> execute(root + "/" + id + "/state", Kind.STATE, nonce, json.writeValueAsBytes(nativeRequest(nonce, true))).join()).hasRootCauseInstanceOf(GroupAuthority.Rejected.class);
  }
  @Test void durableExactBodyReplayRejectsWhitespaceOrCredentialChangesAndEpoch() throws Exception {
    var request = UUID.randomUUID(); byte[] bytes = createBody(request);
    var result = execute(root, Kind.CREATE, request, bytes).join(); assertThat(execute(root, Kind.CREATE, request, bytes).join()).isEqualTo(result);
    byte[] different = (new String(bytes, StandardCharsets.UTF_8) + " ").getBytes(StandardCharsets.UTF_8);
    assertThatThrownBy(() -> execute(root, Kind.CREATE, request, different).join()).hasRootCauseInstanceOf(GroupAuthority.Rejected.class);
    var m = membership; membership = new Membership(m.memberId(), 2, m.signalOperationId(), m.permitId(), m.aci());
    assertThatThrownBy(() -> execute(root, Kind.CREATE, request, bytes).join()).hasRootCauseInstanceOf(GroupAuthority.Rejected.class);
  }
  @Test void callbackWaitNeverOpensSqlAndExpiredCallbackWritesNothing() throws Exception {
    entered = new CountDownLatch(1); release = new CountDownLatch(1); remaining = 100_000_000L;
    var request = UUID.randomUUID(); var pending = execute(root, Kind.CREATE, request, createBody(request));
    assertThat(entered.await(1, TimeUnit.SECONDS)).isTrue(); verify(dataSource, never()).getConnection();
    Thread.sleep(150); release.countDown(); assertThatThrownBy(pending::join).hasRootCauseInstanceOf(SecurityException.class);
    verify(dataSource, never()).getConnection();
    try (var c = db.dataSource.getConnection(); var s = c.createStatement(); var rows = s.executeQuery("SELECT count(*) FROM group_storage.group_namespaces")) {
      rows.next(); assertThat(rows.getLong(1)).isZero();
    }
  }
  @ParameterizedTest @ValueSource(strings = {"actor", "duplicate", "trailing", "compression", "large", "path", "method", "nativeMismatch", "target", "kind"})
  void malformedOrUnsupportedRequestsNeverResolve(String variant) throws Exception {
    var request = UUID.randomUUID(); byte[] body = createBody(request); String path = root, method = "POST", encoding = null;
    String text = new String(body, StandardCharsets.UTF_8);
    switch (variant) {
      case "actor" -> body = json.writeValueAsBytes(((com.fasterxml.jackson.databind.node.ObjectNode) json.readTree(body)).put("actorAci", membership.aci().toString()));
      case "duplicate" -> body = text.replace("\"requestId\":", "\"requestId\":\"" + request + "\",\"requestId\":").getBytes(StandardCharsets.UTF_8);
      case "trailing" -> body = (text + " {}").getBytes(StandardCharsets.UTF_8);
      case "compression" -> encoding = "gzip";
      case "large" -> body = new byte[65537];
      case "path" -> path += "/";
      case "method" -> method = "PUT";
      case "nativeMismatch" -> body = json.writeValueAsBytes(((com.fasterxml.jackson.databind.node.ObjectNode) json.readTree(body)).put("nativeGroup", GroupBridgeProtocol.encode(nativeFixture.submitted.toBuilder().setPublicKey(ByteString.copyFrom(new byte[32])).build().toByteArray())));
      case "target" -> body = json.writeValueAsBytes(((com.fasterxml.jackson.databind.node.ObjectNode) json.readTree(body)).put("targetAci", UUID.randomUUID().toString()));
      case "kind" -> { path += "/" + id + "/changes"; body = json.writeValueAsBytes(nativeRequest(request, false).put("kind", "INVITE").put("expectedRevision", 0)); }
    }
    var result = gateway.execute(method, path, "application/json", encoding, body, binary);
    assertThatThrownBy(result::join).isInstanceOf(java.util.concurrent.CompletionException.class);
    assertThat(calls).hasValue(0); verify(dataSource, never()).getConnection();
  }
}
