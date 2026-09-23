// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.groups.bridge;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.signal.storageservice.groups.bridge.GroupBridgeProtocol.*;

class GroupBridgeTest {
  final String binary = GroupBridgeProtocol.encode(new byte[32]);
  final Operation operation = new Operation("POST", Kind.STATE, binary, UUID.randomUUID(), binary);
  final Membership member = new Membership(UUID.randomUUID(), 1, UUID.randomUUID(), binary, UUID.randomUUID());
  byte[] reply(byte[] request, long nanos) {
    var r = GroupBridgeProtocol.request(request);
    return GroupBridgeProtocol.encode(new Resolution(r.nonce(), r.operation(), member, 1, nanos));
  }
  @Test void strictRoundTripAndFullImmutableBinding() throws Exception {
    var request = new ResolveRequest(binary, binary, operation);
    assertThat(GroupBridgeProtocol.request(GroupBridgeProtocol.encode(request))).isEqualTo(request);
    try (var resolver = new GroupAuthorizationResolver((b, deadline) -> reply(b, 3_900_000_000L), _ -> {}, 1, 1)) {
      var lease = resolver.resolve(binary, operation).get(1, TimeUnit.SECONDS);
      assertThat(lease.membership()).isEqualTo(member); assertThat(lease.aci()).isEqualTo(member.aci());
      assertThat(lease.enrollmentId()).isEqualTo(member.signalOperationId()); assertThat(lease.approvalEpoch()).isEqualTo(1);
      assertThat(lease.deviceId()).isEqualTo(1); lease.requireOperation(operation);
      assertThatThrownBy(() -> lease.requireOperation(new Operation("POST", Kind.STATE, binary, UUID.randomUUID(), binary)))
          .isInstanceOf(SecurityException.class);
    }
  }
  @ParameterizedTest @ValueSource(strings = {"duplicate", "unknown", "trailing", "version", "stringVersion", "oversize", "device", "epoch", "lifetime", "negative", "uuid", "base64", "null", "array"})
  void rejectsMalformedResolution(String mutation) {
    String json = new String(reply(GroupBridgeProtocol.encode(new ResolveRequest(binary, binary, operation)), 3_000_000_000L), StandardCharsets.UTF_8);
    json = switch (mutation) {
      case "duplicate" -> json.replace("\"version\":1", "\"version\":1,\"version\":1");
      case "unknown" -> json.replace("\"version\":1", "\"actor\":\"forged\",\"version\":1");
      case "trailing" -> json + " {}";
      case "version" -> json.replace("\"version\":1", "\"version\":2");
      case "stringVersion" -> json.replace("\"version\":1", "\"version\":\"1\"");
      case "oversize" -> " ".repeat(4097);
      case "device" -> json.replace("\"deviceId\":1", "\"deviceId\":4294967297");
      case "epoch" -> json.replace("\"approvalEpoch\":1", "\"approvalEpoch\":9007199254740992");
      case "lifetime" -> json.replace("3000000000", "4000000001");
      case "negative" -> json.replace("3000000000", "-1");
      case "uuid" -> json.replace(member.aci().toString(), member.aci().toString().toUpperCase());
      case "base64" -> json.replace(binary, binary + "=");
      case "null" -> "null";
      case "array" -> "[]";
      default -> throw new AssertionError();
    };
    byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
    assertThatThrownBy(() -> GroupBridgeProtocol.resolution(bytes)).isInstanceOf(IllegalArgumentException.class);
  }
  @Test void delayedRpcCannotRenewRemainingAtArrival() throws Exception {
    try (var resolver = new GroupAuthorizationResolver((b, deadline) -> { Thread.sleep(150); return reply(b, 100_000_000L); }, _ -> {}, 1, 1)) {
      assertThatThrownBy(() -> resolver.resolve(binary, operation).get(2, TimeUnit.SECONDS)).hasCauseInstanceOf(SecurityException.class);
    }
  }
  @Test void nonceAndEveryOperationBindingAreRequired() throws Exception {
    for (int variant = 0; variant < 5; variant++) {
      int v = variant;
      try (var resolver = new GroupAuthorizationResolver((b, deadline) -> {
        var r = GroupBridgeProtocol.request(b); var o = r.operation();
        var changed = switch (v) {
          case 1 -> new Operation("POST", Kind.TERMINATE, o.groupId(), o.requestId(), o.bodySha256());
          case 2 -> new Operation("POST", Kind.STATE, o.groupId(), UUID.randomUUID(), o.bodySha256());
          case 3 -> new Operation("POST", Kind.STATE, GroupBridgeProtocol.digest(new byte[]{1}), o.requestId(), o.bodySha256());
          case 4 -> new Operation("POST", Kind.STATE, o.groupId(), o.requestId(), GroupBridgeProtocol.digest(new byte[]{1}));
          default -> o;
        };
        return GroupBridgeProtocol.encode(new Resolution(v == 0 ? binary : r.nonce(), changed, member, 1, 3_000_000_000L));
      }, _ -> {}, 1, 1)) {
        assertThatThrownBy(() -> resolver.resolve(binary, operation).get(1, TimeUnit.SECONDS)).hasCauseInstanceOf(SecurityException.class);
      }
    }
  }
  @Test void executorQueueCapacityOriginalDeadlineAndLocalRevocation() throws Exception {
    var entered = new CountDownLatch(1); var release = new CountDownLatch(1); var revoked = new AtomicBoolean();
    try (var resolver = new GroupAuthorizationResolver((b, deadline) -> { entered.countDown(); release.await(); return reply(b, 100_000_000L); },
        _ -> { if (revoked.get()) throw new SecurityException(); }, 1, 1)) {
      var first = resolver.resolve(binary, operation); assertThat(entered.await(1, TimeUnit.SECONDS)).isTrue();
      var queued = resolver.resolve(binary, operation); var overflow = resolver.resolve(binary, operation);
      assertThatThrownBy(overflow::join).hasCauseInstanceOf(java.util.concurrent.RejectedExecutionException.class);
      Thread.sleep(150); release.countDown();
      assertThatThrownBy(first::join).hasCauseInstanceOf(SecurityException.class);
      assertThatThrownBy(queued::join).hasCauseInstanceOf(SecurityException.class);
    } finally { release.countDown(); }
    try (var resolver = new GroupAuthorizationResolver((b, deadline) -> reply(b, 3_000_000_000L), _ -> { if (revoked.get()) throw new SecurityException(); }, 1, 1)) {
      var lease = resolver.resolve(binary, operation).join(); revoked.set(true);
      assertThatThrownBy(lease::requireCurrent).isInstanceOf(SecurityException.class);
    }
  }
  @Test void boundedStreamingBodyCancelsBeforeAccumulatingOversize() {
    var s = mock(Flow.Subscription.class); var body = new GroupVerifierHttpTransport.LimitedBody(); body.onSubscribe(s);
    body.onNext(List.of(ByteBuffer.allocate(4096))); body.onNext(List.of(ByteBuffer.allocate(1)));
    verify(s).cancel(); assertThatThrownBy(() -> body.getBody().toCompletableFuture().join()).hasCauseInstanceOf(java.io.IOException.class);
    var accepted = new GroupVerifierHttpTransport.LimitedBody(); accepted.onSubscribe(mock(Flow.Subscription.class));
    accepted.onNext(List.of(ByteBuffer.wrap(new byte[]{1, 2}))); accepted.onComplete();
    assertThat(accepted.getBody().toCompletableFuture().join()).containsExactly(1, 2);
  }
  @Test void shutdownAndCancellationCannotReleaseQueuedProof() throws Exception {
    var entered = new CountDownLatch(1); var release = new CountDownLatch(1);
    var resolver = new GroupAuthorizationResolver((b, deadline) -> { entered.countDown(); release.await(); return reply(b, 3_000_000_000L); }, _ -> {}, 1, 2);
    try {
      var first = resolver.resolve(binary, operation); assertThat(entered.await(1, TimeUnit.SECONDS)).isTrue();
      var queued = resolver.resolve(binary, operation); queued.cancel(true);
      var next = resolver.resolve(binary, operation); resolver.close();
      assertThat(first).isCompletedExceptionally(); assertThat(queued).isCancelled(); assertThat(next).isCompletedExceptionally();
      assertThat(resolver.resolve(binary, operation)).isCompletedExceptionally();
    } finally { release.countDown(); resolver.close(); }
  }
  @ParameterizedTest @ValueSource(strings = {"http://verifier.test", "https://verifier.test/", "https://verifier.test:443", "https://operator@verifier.test", "https://verifier.test?redirect=evil", "https://verifier.test#x"})
  void transportRequiresExactHttpsOrigin(String origin) {
    assertThatThrownBy(() -> new GroupVerifierHttpTransport(java.net.URI.create(origin), mock(com.google.auth.oauth2.IdTokenProvider.class)))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
