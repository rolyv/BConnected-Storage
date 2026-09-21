// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.controllers;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.ServerSocket;
import java.net.SocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.signal.libsignal.zkgroup.NotarySignature;
import org.signal.storageservice.storage.protos.groups.GroupChange;
import org.signal.storageservice.storage.protos.groups.GroupChangeResponse;
import org.signal.storageservice.storage.protos.groups.GroupResponse;
import org.signal.storageservice.util.SystemMapper;

/** Real loopback HTTP/1.1 through the unchanged production launcher, Jetty and protobuf provider. */
@EnabledIfEnvironmentVariable(named = "BCONNECTED_GROUP_CAPACITY", matches = "true")
@Timeout(value = 5, unit = TimeUnit.MINUTES)
class GroupsHttpCapacityTest {
  private static final String PROTOBUF = "application/x-protobuf";

  @Test
  void eightThousandMembersTraverseActualLauncherAndJettyWith512MiBHeap() throws Exception {
    var evidence = new LinkedHashMap<String, Object>();
    evidence.put("scope", "synthetic loopback HTTP/1.1 through BConnectedStorageLauncher and Jetty");
    evidence.put("members", 8000);
    evidence.put("serverMaximumHeapBytes", 512L * 1024 * 1024);
    evidence.put("javaVersion", System.getProperty("java.version"));
    evidence.put("libsignalVersion", "0.101.2");
    evidence.put("googleIngressTested", false);
    evidence.put("messageDeliveryTested", false);
    evidence.put("realAccountsCreated", 0);
    evidence.put("productionLimitsChanged", false);
    try (var database = new DisposableGroupDatabase()) {
      var fixture = new SyntheticGroupFixture(8000);
      evidence.put("fixtureGenerationMs", fixture.generationMs);
      // Launcher closes its child process before this enclosing database is dropped.
      try (var launcher = LocalLauncher.start(database, fixture)) {
        evidence.put("startupAttempts", launcher.attempts);
        evidence.put("startupMs", launcher.startupMs);
        String admin = fixture.authorization(0);
        String member = fixture.authorization(1);
        assertThat(launcher.request("GET", "/v2/groups", null, null).statusCode()).isEqualTo(401);
        byte[] body = fixture.submitted.toByteArray();
        evidence.put("createRequestBytes", body.length);
        long started = System.nanoTime();
        var create = launcher.request("PUT", "/v2/groups", admin, body);
        evidence.put("createHttpMs", elapsed(started));
        assertThat(create.statusCode()).isEqualTo(200);
        assertThat(create.version()).isEqualTo(HttpClient.Version.HTTP_1_1);
        assertThat(create.headers().firstValue("content-type").orElse("")).startsWith(PROTOBUF);
        var created = GroupResponse.parseFrom(create.body());
        evidence.put("createResponseBytes", create.body().length);
        evidence.put("persistedGroupBytes", created.getGroup().getSerializedSize());
        evidence.put("endorsementBytes", created.getGroupSendEndorsementsResponse().size());
        assertThat(created.getGroup().getMembersCount()).isEqualTo(8000);
        assertThat(created.getGroup().getAnnouncementsOnly()).isTrue();
        assertThat(created.getGroup().getMembersList().stream().map(m -> m.getUserId()).distinct().count())
            .isEqualTo(8000);
        fixture.verifyEndorsements(created);
        var groupId = fixture.authenticatedUser(0).getGroupId();
        assertThat(database.storage.getGroup(groupId).join().orElseThrow().equals(created.getGroup())).isTrue();

        started = System.nanoTime();
        var read = launcher.request("GET", "/v2/groups", member, null);
        evidence.put("memberReadHttpMs", elapsed(started));
        assertThat(read.statusCode()).isEqualTo(200);
        assertThat(GroupResponse.parseFrom(read.body()).getGroup().equals(created.getGroup())).isTrue();
        evidence.put("memberReadResponseBytes", read.body().length);

        var mutation = GroupChange.Actions.newBuilder().setVersion(1)
            .setModifyTitle(GroupChange.Actions.ModifyTitleAction.newBuilder()
                .setTitle(fixture.encryptedTitle("HTTP synthetic announcement update"))).build();
        assertThat(launcher.request("PATCH", "/v2/groups", member, mutation.toByteArray()).statusCode()).isEqualTo(403);
        assertThat(database.storage.getGroup(groupId).join().orElseThrow().getVersion()).isZero();
        started = System.nanoTime();
        var update = launcher.request("PATCH", "/v2/groups", admin, mutation.toByteArray());
        evidence.put("adminSignedUpdateHttpMs", elapsed(started));
        assertThat(update.statusCode()).isEqualTo(200);
        var changed = GroupChangeResponse.parseFrom(update.body());
        fixture.server.getPublicParams().verifySignature(changed.getGroupChange().getActions().toByteArray(),
            new NotarySignature(changed.getGroupChange().getServerSignature().toByteArray()));
        var stored = database.storage.getGroup(groupId).join().orElseThrow();
        assertThat(stored.getVersion()).isEqualTo(1);
        assertThat(stored.getMembersCount()).isEqualTo(8000);
        assertThat(stored.getAnnouncementsOnly()).isTrue();
        var history = database.manager.getChangeRecords(groupId, stored, 7, true, true, 0, 2).join();
        assertThat(history.size()).isEqualTo(2);
        assertThat(history.getLast().getGroupChange().equals(changed.getGroupChange())).isTrue();
        evidence.put("unauthenticatedGetStatus", 401);
        evidence.put("ordinaryMemberMutationStatus", 403);
        evidence.put("adminMutationStatus", 200);
        evidence.put("signedHistoryVerified", true);
      }
    }
    evidence.put("passed", true);
    evidence.put("recordedAt", Instant.now().toString());
    evidence.put("childStoppedAndDisposableDatabaseDropped", true);
    Files.writeString(Path.of("target/group-http-capacity-evidence.json"),
        SystemMapper.getMapper().writerWithDefaultPrettyPrinter().writeValueAsString(evidence));
  }

  private static long elapsed(long start) { return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start); }

  private static final class LocalLauncher implements AutoCloseable {
    final Path privateDirectory;
    final HttpClient client;
    Process process;
    int appPort;
    int attempts;
    long startupMs;

    private LocalLauncher() throws Exception {
      privateDirectory = Files.createTempDirectory("bconnected-group-http-",
          PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
      client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER)
          .version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(2))
          .proxy(new ProxySelector() {
            @Override public List<Proxy> select(URI uri) { return List.of(Proxy.NO_PROXY); }
            @Override public void connectFailed(URI uri, SocketAddress address, IOException error) {}
          }).build();
    }

    static LocalLauncher start(DisposableGroupDatabase database, SyntheticGroupFixture fixture) throws Exception {
      var launcher = new LocalLauncher();
      try {
        byte[] auth = new byte[32];
        byte[] external = new byte[32];
        new SecureRandom().nextBytes(auth);
        new SecureRandom().nextBytes(external);
        Path bundle = launcher.privateDirectory.resolve("fixture-bundle.json");
        Files.createFile(bundle, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        Files.writeString(bundle, SystemMapper.getMapper().writeValueAsString(Map.of(
            "groups.serverSecret", Base64.getEncoder().encodeToString(fixture.server.serialize()),
            "storage.authentication", Base64.getEncoder().encodeToString(auth),
            "groups.externalService", Base64.getEncoder().encodeToString(external))));
        long start = System.nanoTime();
        for (int attempt = 1; attempt <= 3; attempt++) {
          launcher.attempts = attempt;
          int adminPort;
          // Ports remain reserved together until immediately before child launch. Another process
          // can still win the release/bind race; an early startup failure permits at most 3 attempts.
          try (var application = loopbackPort(); var admin = loopbackPort()) {
            launcher.appPort = application.getLocalPort();
            adminPort = admin.getLocalPort();
          }
          var command = new ProcessBuilder(
              Path.of(System.getProperty("java.home"), "bin/java").toString(),
              "--enable-native-access=ALL-UNNAMED", "-Xmx512m",
              "-Djava.io.tmpdir=" + launcher.privateDirectory,
              "-cp", Path.of("target/classes").toAbsolutePath() + ":" + Path.of("target/lib/*").toAbsolutePath(),
              "org.signal.storageservice.BConnectedStorageLauncher");
          // Child receives no inherited cloud/provider credentials, proxy settings or config override.
          var environment = command.environment();
          environment.clear();
          environment.putAll(Map.of(
              "GROUP_STORAGE_SECRETS_FILE", bundle.toString(),
              "GROUP_STORAGE_JDBC_URL", database.jdbcUrl(),
              "GROUP_STORAGE_DB_USER", "postgres",
              "GROUP_STORAGE_PASSWORD_ENV", "BCONNECTED_TEST_POSTGRES_PASSWORD",
              "BCONNECTED_TEST_POSTGRES_PASSWORD", System.getenv("BCONNECTED_TEST_POSTGRES_PASSWORD"),
              "GROUP_STORAGE_BIND_HOST", "127.0.0.1",
              "PORT", Integer.toString(launcher.appPort),
              "GROUP_STORAGE_ADMIN_PORT", Integer.toString(adminPort)));
          // Never propagate child application logs, configuration or credential-bearing requests.
          launcher.process = command.redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
          long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(40);
          while (System.nanoTime() < deadline && launcher.process.isAlive()) {
            try {
              if (launcher.request("GET", "/_ready", null, null).statusCode() == 200
                  && launcher.process.isAlive()) {
                launcher.startupMs = elapsed(start);
                return launcher;
              }
            } catch (IOException ignored) {
              // Readiness retries carry no authorization and never print network response contents.
            }
            Thread.sleep(100);
          }
          launcher.stopChild();
        }
        throw new AssertionError("Fixture launcher did not reach readiness in three bounded attempts");
      } catch (Exception | AssertionError failure) {
        launcher.close();
        throw failure;
      }
    }

    private static ServerSocket loopbackPort() throws IOException {
      var socket = new ServerSocket();
      socket.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0));
      return socket;
    }

    HttpResponse<byte[]> request(String method, String path, String authorization, byte[] body) throws Exception {
      if (!List.of("/v2/groups", "/_ready").contains(path)) throw new IllegalArgumentException("Unexpected fixture route");
      var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + appPort + path))
          .timeout(Duration.ofSeconds(path.equals("/_ready") ? 2 : 30)).header("Accept", PROTOBUF);
      if (authorization != null) request.header("Authorization", authorization);
      if (body != null) request.header("Content-Type", PROTOBUF);
      request.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body));
      return client.send(request.build(), ignored -> new BoundedBody(2 * 1024 * 1024));
    }

    private void stopChild() throws Exception {
      if (process != null) {
        process.destroy();
        if (!process.waitFor(10, TimeUnit.SECONDS)) {
          process.destroyForcibly();
          if (!process.waitFor(5, TimeUnit.SECONDS)) throw new AssertionError("Fixture child failed to stop");
        }
        process = null;
      }
    }

    @Override public void close() throws Exception {
      stopChild();
      client.close();
      try (var paths = Files.walk(privateDirectory)) {
        for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
      }
    }
  }

  private static final class BoundedBody implements HttpResponse.BodySubscriber<byte[]> {
    private final HttpResponse.BodySubscriber<byte[]> delegate = HttpResponse.BodySubscribers.ofByteArray();
    private final long maximum;
    private long received;
    private Flow.Subscription subscription;
    private boolean ended;
    BoundedBody(long maximum) { this.maximum = maximum; }
    @Override public CompletionStage<byte[]> getBody() { return delegate.getBody(); }
    @Override public void onSubscribe(Flow.Subscription subscription) {
      this.subscription = subscription;
      delegate.onSubscribe(subscription);
    }
    @Override public void onNext(List<ByteBuffer> buffers) {
      if (ended) return;
      for (var buffer : buffers) received += buffer.remaining();
      if (received > maximum) {
        ended = true;
        subscription.cancel();
        delegate.onError(new IOException("Oversized local fixture response"));
      } else delegate.onNext(buffers);
    }
    @Override public void onError(Throwable error) { if (!ended) { ended = true; delegate.onError(error); } }
    @Override public void onComplete() { if (!ended) { ended = true; delegate.onComplete(); } }
  }
}
