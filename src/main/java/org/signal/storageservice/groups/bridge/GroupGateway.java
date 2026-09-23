// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.groups.bridge;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.ByteString;
import java.util.Base64;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.signal.libsignal.zkgroup.auth.AuthCredentialPresentation;
import org.signal.libsignal.zkgroup.auth.ServerZkAuthOperations;
import org.signal.libsignal.zkgroup.groups.GroupPublicParams;
import org.signal.storageservice.auth.GroupUser;
import org.signal.storageservice.groups.bridge.GroupBridgeProtocol.Kind;
import org.signal.storageservice.groups.bridge.GroupBridgeProtocol.Operation;
import org.signal.storageservice.groups.manifests.GroupManifestCodec;
import org.signal.storageservice.groups.manifests.GroupManifestService;
import org.signal.storageservice.storage.GroupAuthority;
import org.signal.storageservice.storage.protos.groups.Group;

/** Unregistered application layer. No account authority fields, invite bootstrap, legacy or avatar routes. */
public final class GroupGateway {
  public static final int MAX_BODY_BYTES = 64 * 1024;
  private static final String GROUPS = "/v1/bconnected/groups";
  private static final String OUTCOMES = "/v1/bconnected/group-operations/";
  private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
      .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
      .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(2).maxStringLength(MAX_BODY_BYTES)
          .maxNumberLength(20).build()).build()).enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
  private final GroupAuthorizationResolver resolver;
  private final GroupAuthority authority;
  private final GroupManifestService manifests;
  private final ServerZkAuthOperations zk;
  public GroupGateway(GroupAuthorizationResolver resolver, GroupAuthority authority, GroupManifestService manifests, ServerZkAuthOperations zk) {
    this.resolver = Objects.requireNonNull(resolver); this.authority = Objects.requireNonNull(authority);
    this.manifests = Objects.requireNonNull(manifests); this.zk = Objects.requireNonNull(zk);
  }
  public sealed interface Result permits Committed, Current, Outcome {}
  public record Committed(GroupAuthority.CommittedOutcome outcome) implements Result {}
  /** HTTP registration must set Cache-Control: no-store. Nonce is echoed, not part of the snapshot signature. */
  public record Current(UUID requestNonce, GroupManifestCodec.Envelope envelope) implements Result {}
  public record Outcome(java.util.Optional<GroupAuthority.CommittedOutcome> outcome) implements Result {}
  private record Parsed(Operation operation, GroupUser relationship, Group nativeGroup, long revision, boolean enabled) {}

  /** Private service entry; IAM plus a handle minted by actual authenticated Signal dispatch are required. */
  public CompletableFuture<Result> execute(String method, String path, String contentType, String contentEncoding, byte[] body, String handle) {
    try {
      // Own the bytes before asynchronous work; caller mutation cannot alter the operation's authority.
      if (body == null || body.length > MAX_BODY_BYTES || contentEncoding != null) throw invalid();
      var parsed = parse(method, path, contentType, body.clone());
      return resolver.resolve(handle, parsed.operation).thenCompose(lease -> {
        lease.requireOperation(parsed.operation);
        var o = parsed.operation;
        ByteString requestDigest = ByteString.copyFrom(GroupBridgeProtocol.binary(o.bodySha256(), 32));
        ByteString id = o.kind() == Kind.OUTCOME ? ByteString.EMPTY : ByteString.copyFrom(GroupBridgeProtocol.binary(o.groupId(), 32));
        CompletableFuture<? extends Result> work = switch (o.kind()) {
          case CREATE -> authority.create(lease, o.requestId(), parsed.relationship, parsed.nativeGroup, requestDigest).thenApply(s ->
              new Committed(new GroupAuthority.CommittedOutcome(s.getGroupId(), s.getRevision(), s.getNativeSha256())));
          case STATE -> manifests.current(lease, parsed.relationship, id).thenApply(e -> new Current(o.requestId(), e));
          case ANNOUNCEMENTS, TERMINATE -> authority.change(lease, o.requestId(), parsed.relationship, id, parsed.revision,
              o.kind() == Kind.ANNOUNCEMENTS ? new GroupAuthority.Announcements(parsed.enabled) : new GroupAuthority.Terminate(), requestDigest)
              .thenApply(s -> new Committed(new GroupAuthority.CommittedOutcome(s.getGroupId(), s.getRevision(), s.getNativeSha256())));
          case OUTCOME -> authority.outcome(lease, o.requestId()).thenApply(Outcome::new);
        };
        return work.thenApply(result -> { lease.requireOperation(o); return (Result) result; });
      });
    } catch (Exception failure) { return CompletableFuture.failedFuture(failure); }
  }
  private Parsed parse(String method, String path, String type, byte[] body) throws Exception {
    if (path == null) throw invalid();
    if ("GET".equals(method) && path.startsWith(OUTCOMES)) {
      if (body.length != 0 || type != null) throw invalid();
      return new Parsed(new Operation(method, Kind.OUTCOME, "", GroupBridgeProtocol.uuid(path.substring(OUTCOMES.length())), GroupBridgeProtocol.digest(body)), null, null, 0, false);
    }
    if (!"POST".equals(method) || !"application/json".equals(type) || body.length == 0) throw invalid();
    var n = JSON.readTree(body);
    Kind kind; String suppliedId = null;
    if (GROUPS.equals(path)) { kind = Kind.CREATE; keys(n, "requestId", "groupPublicParams", "groupAuthPresentation", "nativeGroup"); }
    else {
      if (!path.startsWith(GROUPS + "/")) throw invalid();
      var suffix = path.substring(GROUPS.length() + 1).split("/", -1);
      if (suffix.length != 2) throw invalid();
      suppliedId = suffix[0]; GroupBridgeProtocol.binary(suppliedId, 32);
      if (suffix[1].equals("state")) { kind = Kind.STATE; keys(n, "requestNonce", "groupPublicParams", "groupAuthPresentation"); }
      else if (suffix[1].equals("changes")) {
        kind = Kind.valueOf(string(n, "kind"));
        if (kind == Kind.ANNOUNCEMENTS) keys(n, "requestId", "expectedRevision", "groupPublicParams", "groupAuthPresentation", "kind", "enabled");
        else if (kind == Kind.TERMINATE) keys(n, "requestId", "expectedRevision", "groupPublicParams", "groupAuthPresentation", "kind");
        else throw invalid();
      } else throw invalid();
    }
    var request = GroupBridgeProtocol.uuid(string(n, kind == Kind.STATE ? "requestNonce" : "requestId"));
    var params = new GroupPublicParams(binary(n, "groupPublicParams", 1024));
    String id = GroupBridgeProtocol.encode(params.getGroupIdentifier().serialize());
    if (suppliedId != null && !suppliedId.equals(id)) throw invalid();
    var presentation = new AuthCredentialPresentation(binary(n, "groupAuthPresentation", 4096));
    zk.verifyAuthCredentialPresentation(params, presentation);
    var user = new GroupUser(ByteString.copyFrom(presentation.getUuidCiphertext().serialize()),
        presentation.getPniCiphertext() == null ? null : ByteString.copyFrom(presentation.getPniCiphertext().serialize()),
        ByteString.copyFrom(params.serialize()), ByteString.copyFrom(params.getGroupIdentifier().serialize()));
    Group nativeGroup = null;
    if (kind == Kind.CREATE) {
      nativeGroup = Group.parseFrom(binary(n, "nativeGroup", MAX_BODY_BYTES));
      if (!nativeGroup.getPublicKey().equals(ByteString.copyFrom(params.serialize()))) throw invalid();
    }
    long revision = 0; boolean enabled = false;
    if (kind == Kind.ANNOUNCEMENTS || kind == Kind.TERMINATE) {
      var r = n.get("expectedRevision");
      if (!r.isIntegralNumber() || !r.canConvertToLong() || r.longValue() < 0 || r.longValue() > 0xffff_ffffL) throw invalid();
      revision = r.longValue();
      if (kind == Kind.ANNOUNCEMENTS) { var v = n.get("enabled"); if (!v.isBoolean()) throw invalid(); enabled = v.booleanValue(); }
    }
    return new Parsed(new Operation(method, kind, id, request, GroupBridgeProtocol.digest(body)), user, nativeGroup, revision, enabled);
  }
  private static void keys(JsonNode n, String... names) {
    if (n == null || !n.isObject()) throw invalid(); var found = new HashSet<String>(); n.fieldNames().forEachRemaining(found::add);
    if (!found.equals(Set.of(names))) throw invalid();
  }
  private static String string(JsonNode n, String key) { var v = n.get(key); if (v == null || !v.isTextual()) throw invalid(); return v.textValue(); }
  private static byte[] binary(JsonNode n, String key, int max) {
    var s = string(n, key); if (s.isEmpty() || s.length() > (max * 8 + 5) / 6 || !s.matches("[A-Za-z0-9_-]+")) throw invalid();
    var b = Base64.getUrlDecoder().decode(s); if (b.length > max || !GroupBridgeProtocol.encode(b).equals(s)) throw invalid(); return b;
  }
  private static IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid group gateway request"); }
}
