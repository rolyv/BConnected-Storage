// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.groups.manifests;

import static org.signal.storageservice.groups.manifests.GroupManifestCodec.require;
import com.google.protobuf.ByteString;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.signal.storageservice.auth.GroupUser;
import org.signal.storageservice.groups.manifests.GroupManifestCodec.Envelope;
import org.signal.storageservice.groups.manifests.GroupManifestCodec.Failure;
import org.signal.storageservice.groups.manifests.GroupManifestCodec.Rejected;
import org.signal.storageservice.storage.GroupAuthority;

/** Unregistered current-snapshot release boundary. No remote key lookup, provisioning or route. */
public final class GroupManifestService implements AutoCloseable {
  private final GroupAuthority authority;
  private final GroupManifestCodec codec;
  private final String keyId;
  private final JWSSigner signer;
  private final ExecutorService signing;
  private final java.util.Set<CompletableFuture<Envelope>> pending = java.util.concurrent.ConcurrentHashMap.newKeySet();
  private final Object lifecycle = new Object();
  private volatile boolean closed;

  public GroupManifestService(GroupAuthority authority, GroupManifestCodec codec, OctetKeyPair signingKey) {
    this(authority, codec, keyId(signingKey, codec), signer(signingKey), boundedExecutor());
  }

  // Package-private injection is for deterministic signer wait/failure tests, not runtime configuration.
  GroupManifestService(GroupAuthority authority, GroupManifestCodec codec, String keyId,
      JWSSigner signer, ExecutorService signing) {
    this.authority = Objects.requireNonNull(authority);
    this.codec = Objects.requireNonNull(codec);
    this.keyId = keyId;
    codec.currentKey(keyId);
    this.signer = Objects.requireNonNull(signer);
    this.signing = Objects.requireNonNull(signing);
  }

  private static String keyId(OctetKeyPair key, GroupManifestCodec codec) {
    Objects.requireNonNull(key); Objects.requireNonNull(codec);
    require(key.isPrivate() && Curve.Ed25519.equals(key.getCurve())
        && com.nimbusds.jose.JWSAlgorithm.Ed25519.equals(key.getAlgorithm())
        && com.nimbusds.jose.jwk.KeyUse.SIGNATURE.equals(key.getKeyUse()), Failure.INVALID);
    var pinned = codec.currentKey(key.getKeyID());
    require(pinned.publicKey().getX().equals(key.getX()), Failure.UNTRUSTED_KEY);
    return key.getKeyID();
  }
  private static JWSSigner signer(OctetKeyPair key) {
    try { return new Ed25519Signer(key); }
    catch (Exception invalid) { throw new Rejected(Failure.INVALID); }
  }
  static ExecutorService boundedExecutor() {
    ThreadFactory factory = Thread.ofPlatform().daemon().name("group-manifest-sign-", 0).factory();
    return new ThreadPoolExecutor(2, 2, 0, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(32), factory,
        new ThreadPoolExecutor.AbortPolicy());
  }

  public CompletableFuture<Envelope> current(GroupAuthority.Authorization original, GroupUser relationship,
      ByteString groupId) {
    try {
      require(!closed, Failure.UNAVAILABLE);
      var proof = FrozenProof.capture(original);
      return authority.get(proof, relationship, groupId).thenCompose(snapshot -> {
        proof.requireCurrent();
        final CompletableFuture<Envelope> signed;
        try {
          synchronized (lifecycle) {
            require(!closed, Failure.UNAVAILABLE);
            signed = CompletableFuture.supplyAsync(() -> {
              proof.requireCurrent();
              var result = codec.sign(snapshot, keyId, signer);
              proof.requireCurrent();
              return result;
            }, signing);
            pending.add(signed);
            signed.whenComplete((value, failure) -> pending.remove(signed));
          }
        } catch (RejectedExecutionException saturated) {
          return CompletableFuture.failedFuture(new Rejected(Failure.UNAVAILABLE));
        }
        return signed.thenCompose(envelope -> {
          require(!closed, Failure.UNAVAILABLE);
          proof.requireCurrent();
          // No signing/provider work holds the authority transaction. The second read uses the same
          // frozen proof and rejects any intervening state/role/epoch change, never signing anew.
          return authority.get(proof, relationship, groupId).thenApply(current -> {
            proof.requireCurrent();
            require(!closed, Failure.UNAVAILABLE);
            require(current.equals(snapshot), Failure.STALE);
            proof.requireCurrent();
            return envelope;
          });
        });
      });
    } catch (Exception failure) { return CompletableFuture.failedFuture(failure); }
  }

  private record FrozenProof(GroupAuthority.Authorization original, UUID aci, UUID enrollmentId,
      long approvalEpoch, long expiresAtNanos) implements GroupAuthority.Authorization {
    static FrozenProof capture(GroupAuthority.Authorization original) {
      Objects.requireNonNull(original);
      var proof = new FrozenProof(original, Objects.requireNonNull(original.aci()),
          Objects.requireNonNull(original.enrollmentId()), original.approvalEpoch(), original.expiresAtNanos());
      proof.requireCurrent();
      require(proof.expiresAtNanos - System.nanoTime() <= 4_000_000_000L, Failure.INVALID);
      return proof;
    }
    @Override public void requireCurrent() {
      require(expiresAtNanos - System.nanoTime() > 0, Failure.STALE);
      original.requireCurrent();
      require(aci.equals(original.aci()) && enrollmentId.equals(original.enrollmentId())
          && approvalEpoch == original.approvalEpoch(), Failure.STALE);
      require(expiresAtNanos - System.nanoTime() > 0, Failure.STALE);
    }
    @Override public String toString() { return "GroupManifestOriginalProof[redacted]"; }
  }
  @Override public void close() {
    final java.util.List<CompletableFuture<Envelope>> abandoned;
    synchronized (lifecycle) {
      closed = true;
      abandoned = java.util.List.copyOf(pending);
    }
    // CompletableFuture completion can run caller callbacks inline; never do that under lifecycle.
    signing.shutdownNow();
    for (var future : abandoned) future.completeExceptionally(new Rejected(Failure.UNAVAILABLE));
  }
  @Override public String toString() { return "GroupManifestService[redacted]"; }
}
