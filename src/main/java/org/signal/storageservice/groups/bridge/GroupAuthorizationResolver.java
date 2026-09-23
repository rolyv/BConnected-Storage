// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.groups.bridge;

import java.security.SecureRandom;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.signal.storageservice.groups.bridge.GroupBridgeProtocol.*;
import org.signal.storageservice.storage.GroupAuthority;

/** Resolve exactly once before entering GroupAuthority; no callback or lease renewal under SQL locks. */
public final class GroupAuthorizationResolver implements AutoCloseable {
  /** Deadline is local System.nanoTime, never serialized to the other service. */
  @FunctionalInterface public interface Transport { byte[] resolve(byte[] request, long localDeadlineNanos) throws Exception; }
  /** Must be local/nonblocking. A future revocation projection may only shorten this original lease. */
  @FunctionalInterface public interface Revocations { void requireCurrent(Membership original); }
  private final Transport transport;
  private final Revocations revocations;
  private final SecureRandom random = new SecureRandom();
  private final ThreadPoolExecutor executor;
  private final java.util.Set<CompletableFuture<Lease>> pending = java.util.concurrent.ConcurrentHashMap.newKeySet();
  private final java.util.concurrent.atomic.AtomicBoolean closed = new java.util.concurrent.atomic.AtomicBoolean();

  public GroupAuthorizationResolver(Transport transport, Revocations revocations, int concurrency, int queue) {
    this.transport = Objects.requireNonNull(transport); this.revocations = Objects.requireNonNull(revocations);
    if (concurrency < 1 || concurrency > 16 || queue < 1 || queue > 256) throw new IllegalArgumentException("Invalid resolve capacity");
    executor = new ThreadPoolExecutor(concurrency, concurrency, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(queue),
        Thread.ofPlatform().daemon().name("group-proof-resolve-", 0).factory(), new ThreadPoolExecutor.AbortPolicy());
  }

  /** Private construction prevents client fields or IAM-only requests being adapted directly. */
  public final class Lease implements GroupAuthority.Authorization {
    private final Resolution resolved;
    private final long deadline;
    private Lease(Resolution resolved, long start) { this.resolved = resolved; deadline = start + resolved.remainingNanos(); }
    public UUID aci() { return resolved.membership().aci(); }
    public UUID enrollmentId() { return resolved.membership().signalOperationId(); }
    public long approvalEpoch() { return resolved.membership().approvalEpoch(); }
    public long expiresAtNanos() { return deadline; }
    public Membership membership() { return resolved.membership(); }
    public Operation operation() { return resolved.operation(); }
    public int deviceId() { return resolved.deviceId(); }
    public void requireCurrent() {
      if (deadline - System.nanoTime() <= 0) throw new SecurityException("Group authorization expired");
      revocations.requireCurrent(resolved.membership());
      if (deadline - System.nanoTime() <= 0) throw new SecurityException("Group authorization expired");
    }
    public void requireOperation(Operation expected) {
      if (!resolved.operation().equals(expected)) throw new SecurityException("Group operation binding mismatch"); requireCurrent();
    }
    @Override public String toString() { return "GroupAuthorizationLease[redacted]"; }
  }

  public CompletableFuture<Lease> resolve(String handle, Operation operation) {
    // Include executor queue time in the original local budget. Never start the clock at response arrival.
    long start = System.nanoTime();
    var result = new CompletableFuture<Lease>();
    try {
      if (closed.get()) throw new IllegalStateException("Group resolver closed");
      byte[] entropy = new byte[32]; random.nextBytes(entropy);
      var request = new ResolveRequest(handle, GroupBridgeProtocol.encode(entropy), operation);
      pending.add(result);
      result.whenComplete((_, _) -> pending.remove(result));
      if (closed.get()) throw new IllegalStateException("Group resolver closed");
      var task = executor.submit(() -> {
        try {
          if (result.isDone() || System.nanoTime() - start >= GroupBridgeProtocol.MAX_LIFETIME_NANOS) throw new SecurityException("Group authorization expired");
          var response = GroupBridgeProtocol.resolution(transport.resolve(GroupBridgeProtocol.encode(request), start + GroupBridgeProtocol.MAX_LIFETIME_NANOS));
          if (!response.nonce().equals(request.nonce()) || !response.operation().equals(operation)) throw new SecurityException("Group resolution binding mismatch");
          var lease = new Lease(response, start); lease.requireCurrent(); result.complete(lease);
        } catch (Exception failure) { result.completeExceptionally(failure); }
      });
      result.orTimeout(4, TimeUnit.SECONDS).whenComplete((_, failure) -> { if (failure != null) task.cancel(true); });
      return result;
    } catch (RuntimeException failure) { result.completeExceptionally(failure); return result; }
  }
  @Override public void close() {
    closed.set(true);
    pending.forEach(f -> f.completeExceptionally(new IllegalStateException("Group resolver closed")));
    executor.shutdownNow();
  }
}
