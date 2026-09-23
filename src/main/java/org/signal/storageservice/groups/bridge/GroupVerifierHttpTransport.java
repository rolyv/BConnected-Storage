// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.groups.bridge;

import com.google.auth.oauth2.IdTokenCredentials;
import com.google.auth.oauth2.IdTokenProvider;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;

/** Dedicated Groups ADC OIDC token, exact owned HTTPS origin, no redirects or compression. */
public final class GroupVerifierHttpTransport implements GroupAuthorizationResolver.Transport, AutoCloseable {
  private final URI endpoint;
  private final IdTokenCredentials credentials;
  private final HttpClient client;
  public GroupVerifierHttpTransport(URI fixedSignalOrigin, IdTokenProvider dedicatedRuntimeProvider) {
    this(fixedSignalOrigin, IdTokenCredentials.newBuilder().setIdTokenProvider(Objects.requireNonNull(dedicatedRuntimeProvider))
        .setTargetAudience(origin(fixedSignalOrigin)).build(),
        HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(1)).followRedirects(HttpClient.Redirect.NEVER).build());
  }
  GroupVerifierHttpTransport(URI fixedSignalOrigin, IdTokenCredentials credentials, HttpClient client) {
    origin(fixedSignalOrigin);
    if (client.followRedirects() != HttpClient.Redirect.NEVER) throw new IllegalArgumentException("Verifier redirects forbidden");
    endpoint = fixedSignalOrigin.resolve(GroupBridgeProtocol.RESOLVE_PATH);
    this.credentials = Objects.requireNonNull(credentials); this.client = Objects.requireNonNull(client);
  }
  private static String origin(URI fixedSignalOrigin) {
    if (fixedSignalOrigin == null || !"https".equals(fixedSignalOrigin.getScheme()) || fixedSignalOrigin.getHost() == null
        || fixedSignalOrigin.getPort() != -1 || !fixedSignalOrigin.getPath().isEmpty() || fixedSignalOrigin.getUserInfo() != null
        || fixedSignalOrigin.getQuery() != null || fixedSignalOrigin.getFragment() != null)
      throw new IllegalArgumentException("Fixed HTTPS Signal verifier origin required");
    return fixedSignalOrigin.toString();
  }
  @Override public byte[] resolve(byte[] body, long localDeadlineNanos) throws Exception {
    GroupBridgeProtocol.request(body);
    requireRemaining(localDeadlineNanos);
    credentials.refreshIfExpired();
    // Credential providers need not honor interruption. Never dispatch after a late return.
    requireRemaining(localDeadlineNanos);
    var token = credentials.getIdToken();
    if (token == null || token.getTokenValue().length() > 8192) throw new IOException("Group verifier identity unavailable");
    long httpNanos = Math.min(TimeUnit.SECONDS.toNanos(2), requireRemaining(localDeadlineNanos));
    var request = HttpRequest.newBuilder(endpoint).timeout(Duration.ofNanos(httpNanos))
        .header("Authorization", "Bearer " + token.getTokenValue()).header("Content-Type", "application/json")
        .header("Accept", "application/json").POST(HttpRequest.BodyPublishers.ofByteArray(body)).build();
    requireRemaining(localDeadlineNanos);
    var response = client.sendAsync(request, _ -> new LimitedBody());
    try {
      var result = response.get(Math.min(httpNanos, requireRemaining(localDeadlineNanos)), TimeUnit.NANOSECONDS);
      if (result.statusCode() != 200 || !result.headers().allValues("content-encoding").isEmpty()
          || !result.headers().allValues("content-type").equals(List.of("application/json")))
        throw new IOException("Group verifier unavailable");
      return result.body();
    } catch (Exception failure) { response.cancel(true); throw failure; }
  }
  private static long requireRemaining(long deadline) throws java.util.concurrent.TimeoutException, InterruptedException {
    if (Thread.currentThread().isInterrupted()) throw new InterruptedException("Group verifier interrupted");
    long remaining = deadline - System.nanoTime();
    if (remaining <= 0 || remaining > GroupBridgeProtocol.MAX_LIFETIME_NANOS) throw new java.util.concurrent.TimeoutException("Group verifier deadline exceeded");
    return remaining;
  }
  /** Limits bytes as they arrive, before allocation; the whole body also has a two-second deadline. */
  static final class LimitedBody implements HttpResponse.BodySubscriber<byte[]> {
    private final CompletableFuture<byte[]> result = new CompletableFuture<>();
    private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    private Flow.Subscription subscription;
    @Override public CompletionStage<byte[]> getBody() { return result; }
    @Override public void onSubscribe(Flow.Subscription s) { subscription = s; s.request(1); }
    @Override public void onNext(List<ByteBuffer> items) {
      try {
        for (var item : items) {
          if (item.remaining() > GroupBridgeProtocol.MAX_WIRE_BYTES - bytes.size()) throw new IOException("Group verifier response too large");
          byte[] chunk = new byte[item.remaining()]; item.get(chunk); bytes.writeBytes(chunk);
        }
        subscription.request(1);
      } catch (Exception failure) { subscription.cancel(); result.completeExceptionally(failure); }
    }
    @Override public void onError(Throwable failure) { result.completeExceptionally(failure); }
    @Override public void onComplete() { result.complete(bytes.toByteArray()); }
  }
  @Override public void close() { client.shutdownNow(); }
  @Override public String toString() { return "GroupVerifierHttpTransport[redacted]"; }
}
