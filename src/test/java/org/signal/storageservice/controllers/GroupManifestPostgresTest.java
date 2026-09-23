// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.controllers;

import static org.assertj.core.api.Assertions.*;
import com.google.protobuf.ByteString;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCredentialPresentation;
import org.signal.storageservice.auth.GroupUser;
import org.signal.storageservice.configuration.GroupConfiguration;
import org.signal.storageservice.groups.manifests.GroupManifestCodec;
import org.signal.storageservice.groups.manifests.GroupManifestCodec.*;
import org.signal.storageservice.groups.manifests.GroupManifestService;
import org.signal.storageservice.groups.manifests.ManifestTestSupport;
import org.signal.storageservice.storage.GroupAuthority;
import org.signal.storageservice.storage.GroupAuthority.*;
import org.signal.storageservice.storage.protos.groups.*;

@EnabledIfEnvironmentVariable(named = "BCONNECTED_GROUP_TEST_JDBC_URL", matches = ".+")
class GroupManifestPostgresTest {
  final DisposableGroupDatabase db = new DisposableGroupDatabase();
  final SyntheticGroupFixture fixture = new SyntheticGroupFixture(3);
  final ExecutorService executor = Executors.newFixedThreadPool(8);
  final GroupAuthority authority = new GroupAuthority(db.dataSource, executor, fixture.server,
      new GroupConfiguration(8000, 1024, 8192, new byte[32], null, null), Clock.systemUTC());
  final List<UUID> acis = fixture.identities.stream().map(x -> ((Aci)x).getRawUUID()).toList();
  final List<UUID> enrollments = List.of(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID());
  final List<GroupUser> users = List.of(fixture.authenticatedUser(0), fixture.authenticatedUser(1), fixture.authenticatedUser(2));
  final ByteString id = users.getFirst().getGroupId();
  final Group creation = fixture.submitted.toBuilder().clearMembers().addMembers(fixture.submitted.getMembers(0)).build();
  final OctetKeyPair key = GroupManifestCodecTest.key("native-manifest-test");
  final GroupManifestCodec codec = new GroupManifestCodec(Map.of(key.getKeyID(), new TrustedKey(key.toPublicJWK(), true)));
  final List<GroupManifestService> services = new ArrayList<>();
  final List<BlockingSigner> blockers = new ArrayList<>();
  GroupManifestPostgresTest() throws Exception {}
  @AfterEach void cleanup() throws Exception {
    blockers.forEach(b -> b.release.countDown()); services.forEach(GroupManifestService::close); executor.close(); db.close();
  }
  class Proof implements Authorization {
    volatile UUID aci, enrollment;
    volatile long epoch = 1, deadline;
    volatile boolean revoked;
    Proof(int who) { aci = acis.get(who); enrollment = enrollments.get(who); deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(3900); }
    public UUID aci() { return aci; }
    public UUID enrollmentId() { return enrollment; }
    public long approvalEpoch() { return epoch; }
    public long expiresAtNanos() { return deadline; }
    public void requireCurrent() { if (revoked) throw new SecurityException("Synthetic revoked proof"); }
  }
  Proof proof(int who) { return new Proof(who); }
  void create() { authority.create(proof(0), UUID.randomUUID(), users.get(0), creation).join(); }
  void change(int who, long revision, Change change) { authority.change(proof(who), UUID.randomUUID(), users.get(who), id, revision, change).join(); }
  void addSecondAdmin() throws Exception {
    var principal = ByteString.copyFrom(new ProfileKeyCredentialPresentation(fixture.submitted.getMembers(1).getPresentation().toByteArray()).getUuidCiphertext().serialize());
    change(0, 0, new Invite(proof(1), principal)); change(1, 1, new Accept(fixture.submitted.getMembers(1).getPresentation()));
    change(0, 2, new SetRole(acis.get(1), Member.Role.ADMINISTRATOR));
  }
  GroupManifestService service(JWSSigner signer) {
    var result = ManifestTestSupport.service(authority, codec, key.getKeyID(), signer); services.add(result); return result;
  }
  GroupManifestService service() throws Exception { return service(new Ed25519Signer(key)); }
  class BlockingSigner implements JWSSigner {
    final Ed25519Signer actual = new Ed25519Signer(key);
    final CountDownLatch entered;
    final CountDownLatch release = new CountDownLatch(1);
    final AtomicInteger calls = new AtomicInteger();
    volatile boolean fail;
    BlockingSigner(int count) throws Exception { entered = new CountDownLatch(count); blockers.add(this); }
    public Set<JWSAlgorithm> supportedJWSAlgorithms() { return actual.supportedJWSAlgorithms(); }
    public JCAContext getJCAContext() { return actual.getJCAContext(); }
    public Base64URL sign(JWSHeader header, byte[] input) throws JOSEException {
      calls.incrementAndGet(); entered.countDown();
      try { if (!release.await(5, TimeUnit.SECONDS)) throw new JOSEException("Synthetic signer stalled"); }
      catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new JOSEException("Synthetic signer interrupted"); }
      if (fail) throw new JOSEException("Synthetic signer unavailable");
      return actual.sign(header, input);
    }
    void awaitEntry() throws Exception { assertThat(entered.await(2, TimeUnit.SECONDS)).isTrue(); }
  }
  static void denied(CompletableFuture<?> value) {
    assertThatThrownBy(() -> value.get(6, TimeUnit.SECONDS)).isInstanceOf(java.util.concurrent.ExecutionException.class);
  }
  @Test void currentManifestUsesRealAuthoritativeSnapshotAndPinnedPublicKey() throws Exception {
    create(); var envelope = service().current(proof(0), users.get(0), id).get(3, TimeUnit.SECONDS);
    var verified = codec.verify(envelope, id, KnownState.none(), Purpose.CURRENT_RESPONSE);
    assertThat(verified.roster()).singleElement().satisfies(e -> assertThat(e.aci()).isEqualTo(acis.get(0)));
    assertThat(verified.nativeBytes()).isEqualTo(authority.get(proof(0), users.get(0), id).join().getNativeGroup());
    assertThat(verified.revision()).isZero();
  }
  @Test void revisionChangeDuringSigningDoesNotHoldSqlLockAndSuppressesOldResult() throws Exception {
    create(); var signer = new BlockingSigner(1); var pending = service(signer).current(proof(0), users.get(0), id); signer.awaitEntry();
    change(0, 0, new Announcements(false)); // Completes while signing is blocked: no authority SQL lock is held.
    signer.release.countDown(); denied(pending);
    assertThat(authority.get(proof(0), users.get(0), id).join().getRevision()).isEqualTo(1);
    assertThat(signer.calls).hasValue(1); // No silent retry/renewal/re-sign with changed authority.
  }
  @ParameterizedTest @ValueSource(strings = {"revoked", "epoch", "enrollment", "aci"})
  void originalBindingChangeDuringSigningSuppressesResponse(String kind) throws Exception {
    create(); var signer = new BlockingSigner(1); var proof = proof(0);
    var pending = service(signer).current(proof, users.get(0), id); signer.awaitEntry();
    switch (kind) { case "revoked" -> proof.revoked = true; case "epoch" -> proof.epoch++; case "enrollment" -> proof.enrollment = UUID.randomUUID(); case "aci" -> proof.aci = UUID.randomUUID(); }
    signer.release.countDown(); denied(pending);
  }
  @Test void renewedDeadlineCannotExtendWorkAlreadyWaitingInSigner() throws Exception {
    create(); var signer = new BlockingSigner(1); var proof = proof(0); proof.deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(250);
    var pending = service(signer).current(proof, users.get(0), id); signer.awaitEntry();
    long original = proof.deadline; proof.deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(3900);
    TimeUnit.NANOSECONDS.sleep(Math.max(0, original - System.nanoTime()) + TimeUnit.MILLISECONDS.toNanos(20));
    signer.release.countDown(); denied(pending); assertThat(signer.calls).hasValue(1);
  }
  @ParameterizedTest @ValueSource(strings = {"remove", "demote", "terminate"})
  void authorityChangesAfterFirstReadCannotReleasePriorSnapshot(String change) throws Exception {
    create(); addSecondAdmin(); var signer = new BlockingSigner(1);
    var pending = service(signer).current(proof(0), users.get(0), id); signer.awaitEntry();
    switch (change) { case "remove" -> change(1, 3, new Remove(acis.get(0))); case "demote" -> change(1, 3, new SetRole(acis.get(0), Member.Role.DEFAULT)); case "terminate" -> change(1, 3, new Terminate()); }
    signer.release.countDown(); denied(pending);
  }
  @ParameterizedTest @ValueSource(strings = {"wrongAci", "wrongZk", "epoch", "enrollment", "expired", "longDeadline", "badId", "nullId"})
  void invalidCallerNeverReachesSigner(String kind) throws Exception {
    create(); var signer = new BlockingSigner(1); var proof = proof(0); var user = users.get(0); ByteString groupId = id;
    switch (kind) { case "wrongAci" -> proof = proof(1); case "wrongZk" -> user = users.get(1); case "epoch" -> proof.epoch++; case "enrollment" -> proof.enrollment = UUID.randomUUID(); case "expired" -> proof.deadline = System.nanoTime() - 1; case "longDeadline" -> proof.deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10); case "badId" -> groupId = ByteString.copyFromUtf8("short"); case "nullId" -> groupId = null; }
    denied(service(signer).current(proof, user, groupId)); assertThat(signer.calls).hasValue(0);
  }
  @Test void signerFailureAndMismatchedPrivateKeyFailClosed() throws Exception {
    create(); var signer = new BlockingSigner(1); signer.fail = true; signer.release.countDown();
    denied(service(signer).current(proof(0), users.get(0), id));
    var wrong = GroupManifestCodecTest.key(key.getKeyID());
    assertThatThrownBy(() -> new GroupManifestService(authority, codec, wrong)).isInstanceOf(GroupManifestCodec.Rejected.class);
    denied(service(new Ed25519Signer(wrong)).current(proof(0), users.get(0), id));
  }
  @Test void historicalSignatureDoesNotRestoreReadAfterTermination() throws Exception {
    create(); var manifests = service(); var envelope = manifests.current(proof(0), users.get(0), id).join();
    change(0, 0, new Terminate());
    denied(manifests.current(proof(0), users.get(0), id));
    assertThat(codec.verify(envelope, id, KnownState.none(), Purpose.HISTORICAL_SNAPSHOT).revision()).isZero();
  }
  @Test void boundedSignerQueueRejectsSaturationAndRecoversAfterRawSigningCompletes() throws Exception {
    create(); var signer = new BlockingSigner(2); var manifests = service(signer); var results = new ArrayList<CompletableFuture<Envelope>>();
    results.add(manifests.current(proof(0), users.get(0), id)); results.add(manifests.current(proof(0), users.get(0), id)); signer.awaitEntry();
    for (int i = 0; i < 33; i++) results.add(manifests.current(proof(0), users.get(0), id));
    CompletableFuture.anyOf(results.toArray(CompletableFuture[]::new)).handle((v, e) -> null).get(3, TimeUnit.SECONDS);
    assertThat(results.stream().filter(CompletableFuture::isCompletedExceptionally).count()).isEqualTo(1);
    assertThat(signer.calls).hasValue(2);
    signer.release.countDown();
    CompletableFuture.allOf(results.stream().map(f -> f.handle((v,e) -> null)).toArray(CompletableFuture[]::new)).get(4, TimeUnit.SECONDS);
    assertThat(results.stream().filter(f -> !f.isCompletedExceptionally()).count()).isEqualTo(34);
    assertThat(manifests.current(proof(0), users.get(0), id).get(2, TimeUnit.SECONDS)).isNotNull();
  }
  @Test void cancellationCannotFreeWorkerAndRenewalCannotExtendQueuedProof() throws Exception {
    create(); var signer = new BlockingSigner(2); var manifests = service(signer);
    var first = manifests.current(proof(0), users.get(0), id);
    var second = manifests.current(proof(0), users.get(0), id); signer.awaitEntry();
    assertThat(first.cancel(false)).isTrue();
    var queuedProof = proof(0); queuedProof.deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(200);
    var queued = manifests.current(queuedProof, users.get(0), id);
    long deadline = queuedProof.deadline;
    // Canceling the outward future must not release the raw signing worker.
    TimeUnit.MILLISECONDS.sleep(50); assertThat(queued).isNotDone(); assertThat(signer.calls).hasValue(2);
    queuedProof.deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(3900);
    TimeUnit.NANOSECONDS.sleep(Math.max(0, deadline - System.nanoTime()) + TimeUnit.MILLISECONDS.toNanos(20));
    signer.release.countDown(); second.get(2, TimeUnit.SECONDS); denied(queued);
    assertThat(signer.calls).hasValue(2); // Expired queue work never calls the signer.
  }
  @Test void shutdownCompletesWaitingAndQueuedResponsesWithoutLeakingSignatures() throws Exception {
    create(); var signer = new BlockingSigner(2); var manifests = service(signer); var results = new ArrayList<CompletableFuture<Envelope>>();
    for (int i = 0; i < 6; i++) results.add(manifests.current(proof(0), users.get(0), id));
    signer.awaitEntry(); manifests.close();
    for (var result : results) denied(result);
    denied(manifests.current(proof(0), users.get(0), id));
  }
}
