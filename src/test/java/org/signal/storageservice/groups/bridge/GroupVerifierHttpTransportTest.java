// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.groups.bridge;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.google.auth.oauth2.IdToken;
import com.google.auth.oauth2.IdTokenCredentials;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.signal.storageservice.groups.bridge.GroupBridgeProtocol.*;

/** HTTP client and token source fault injection; this does not assert owned live TLS/OIDC reachability. */
class GroupVerifierHttpTransportTest {
  final HttpClient http = mock(HttpClient.class);
  final IdTokenCredentials credentials = mock(IdTokenCredentials.class);
  final String binary = GroupBridgeProtocol.encode(new byte[32]);
  final Operation operation = new Operation("POST", Kind.STATE, binary, UUID.randomUUID(), binary);
  final byte[] request = GroupBridgeProtocol.encode(new ResolveRequest(binary, binary, operation));
  GroupVerifierHttpTransportTest() {
    when(http.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
    var token = mock(IdToken.class); when(token.getTokenValue()).thenReturn("synthetic.private.token"); when(credentials.getIdToken()).thenReturn(token);
  }
  GroupVerifierHttpTransport transport() { return new GroupVerifierHttpTransport(URI.create("https://verifier.example.test"), credentials, http); }
  @SuppressWarnings("unchecked") HttpResponse<byte[]> response(int status, Map<String, List<String>> headers) {
    HttpResponse<byte[]> r = mock(HttpResponse.class); when(r.statusCode()).thenReturn(status);
    when(r.headers()).thenReturn(HttpHeaders.of(headers, (_, _) -> true)); when(r.body()).thenReturn(new byte[]{1}); return r;
  }
  @Test void exactFixedRequestHasOidcTokenAndNoRedirects() throws Exception {
    when(http.<byte[]>sendAsync(any(), any())).thenAnswer(invocation -> {
      HttpRequest r = invocation.getArgument(0);
      assertThat(r.uri().toString()).isEqualTo("https://verifier.example.test" + GroupBridgeProtocol.RESOLVE_PATH);
      assertThat(r.method()).isEqualTo("POST"); assertThat(r.headers().firstValue("Authorization")).contains("Bearer synthetic.private.token");
      assertThat(r.headers().firstValue("Content-Type")).contains("application/json"); assertThat(r.timeout()).contains(java.time.Duration.ofSeconds(2));
      return CompletableFuture.completedFuture(response(200, Map.of("Content-Type", List.of("application/json"))));
    });
    try (var t = transport()) { assertThat(t.resolve(request, System.nanoTime() + 4_000_000_000L)).containsExactly(1); }
    verify(credentials).refreshIfExpired();
  }
  @ParameterizedTest @ValueSource(strings = {"redirect", "operatorDenied", "compressed", "unknownType", "duplicateType"})
  void rejectsRedirectStatusAndContentContract(String variant) throws Exception {
    int status = variant.equals("redirect") ? 302 : variant.equals("operatorDenied") ? 403 : 200;
    var headers = new java.util.HashMap<>(Map.of("Content-Type", List.of("application/json")));
    if (variant.equals("compressed")) headers.put("Content-Encoding", List.of("gzip"));
    if (variant.equals("unknownType")) headers.put("Content-Type", List.of("text/plain"));
    if (variant.equals("duplicateType")) headers.put("Content-Type", List.of("application/json", "application/json"));
    var received = response(status, headers);
    when(http.<byte[]>sendAsync(any(), any())).thenReturn(CompletableFuture.completedFuture(received));
    try (var t = transport()) { assertThatThrownBy(() -> t.resolve(request, System.nanoTime() + 4_000_000_000L)).isInstanceOf(java.io.IOException.class); }
    verify(http, times(1)).sendAsync(any(), any());
  }
  @Test void slowResponseBodyCancelsWithinRequestDeadline() {
    var stalled = new CompletableFuture<HttpResponse<byte[]>>(); when(http.<byte[]>sendAsync(any(), any())).thenReturn(stalled);
    try (var t = transport()) { assertThatThrownBy(() -> t.resolve(request, System.nanoTime() + 4_000_000_000L)).isInstanceOf(java.util.concurrent.TimeoutException.class); }
    assertThat(stalled).isCancelled();
  }
  @Test void oidcRefreshWaitConsumesOriginalResolverDeadlineAndDoesNotDispatch() throws Exception {
    var entered = new CountDownLatch(1); var release = new CountDownLatch(1); var stopped = new CountDownLatch(1);
    doAnswer(_ -> {
      entered.countDown();
      while (release.getCount() != 0) { try { release.await(); } catch (InterruptedException ignored) { /* Synthetic uninterruptible provider. */ } }
      return null;
    }).when(credentials).refreshIfExpired();
    try (var t = transport(); var resolver = new GroupAuthorizationResolver((b, deadline) -> { try { return t.resolve(b, deadline); } finally { stopped.countDown(); } }, _ -> {}, 1, 1)) {
      var result = resolver.resolve(binary, operation); assertThat(entered.await(1, TimeUnit.SECONDS)).isTrue();
      assertThatThrownBy(() -> result.get(5, TimeUnit.SECONDS)).hasCauseInstanceOf(java.util.concurrent.TimeoutException.class);
      release.countDown(); assertThat(stopped.await(1, TimeUnit.SECONDS)).isTrue();
      verify(http, never()).sendAsync(any(), any());
    } finally { release.countDown(); }
  }
}
