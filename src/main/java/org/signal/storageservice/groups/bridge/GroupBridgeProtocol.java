// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.groups.bridge;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/** Version-one private wire. This is data, never a source of authorization by itself. */
public final class GroupBridgeProtocol {
  public static final long MAX_LIFETIME_NANOS = 4_000_000_000L;
  public static final int MAX_WIRE_BYTES = 4096;
  public static final String RESOLVE_PATH = "/internal/v1/bconnected/group-authorizations/resolve";
  private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
      .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
      .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(4).maxStringLength(1024)
          .maxNumberLength(20).build()).build()).enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
  private GroupBridgeProtocol() {}

  public enum Kind { CREATE, STATE, ANNOUNCEMENTS, TERMINATE, OUTCOME }
  public record Operation(String method, Kind kind, String groupId, UUID requestId, String bodySha256) {
    public Operation {
      require(kind != null && requestId != null);
      require((kind == Kind.OUTCOME ? "GET" : "POST").equals(method));
      if (kind == Kind.OUTCOME) require("".equals(groupId)); else binary(groupId, 32);
      binary(bodySha256, 32);
    }
    @Override public String toString() { return "GroupOperation[redacted]"; }
  }
  public record ResolveRequest(String handle, String nonce, Operation operation) {
    public ResolveRequest { binary(handle, 32); binary(nonce, 32); require(operation != null); }
    @Override public String toString() { return "GroupResolveRequest[redacted]"; }
  }
  public record Membership(UUID memberId, long approvalEpoch, UUID signalOperationId, String permitId, UUID aci) {
    public Membership {
      require(memberId != null && signalOperationId != null && aci != null);
      require(approvalEpoch >= 0 && approvalEpoch <= 9_007_199_254_740_991L); binary(permitId, 32);
    }
    @Override public String toString() { return "GroupMembership[redacted]"; }
  }
  public record Resolution(String nonce, Operation operation, Membership membership, int deviceId, long remainingNanos) {
    public Resolution {
      binary(nonce, 32); require(operation != null && membership != null && deviceId == 1);
      require(remainingNanos > 0 && remainingNanos <= MAX_LIFETIME_NANOS);
    }
    @Override public String toString() { return "GroupResolution[redacted]"; }
  }
  public static byte[] encode(ResolveRequest value) {
    var root = JSON.createObjectNode().put("version", 1).put("handle", value.handle).put("nonce", value.nonce);
    root.set("operation", operation(value.operation)); return bytes(root);
  }
  public static byte[] encode(Resolution value) {
    var root = JSON.createObjectNode().put("version", 1).put("nonce", value.nonce)
        .put("deviceId", value.deviceId).put("remainingNanos", value.remainingNanos);
    root.set("operation", operation(value.operation));
    var member = root.putObject("membership");
    member.put("memberId", value.membership.memberId.toString()).put("approvalEpoch", value.membership.approvalEpoch)
        .put("signalOperationId", value.membership.signalOperationId.toString())
        .put("permitId", value.membership.permitId).put("aci", value.membership.aci.toString());
    return bytes(root);
  }
  public static ResolveRequest request(byte[] bytes) {
    var root = tree(bytes); keys(root, "version", "handle", "nonce", "operation"); version(root);
    return new ResolveRequest(string(root, "handle"), string(root, "nonce"), operation(root.get("operation")));
  }
  public static Resolution resolution(byte[] bytes) {
    var root = tree(bytes); keys(root, "version", "nonce", "operation", "membership", "deviceId", "remainingNanos"); version(root);
    var m = root.get("membership"); keys(m, "memberId", "approvalEpoch", "signalOperationId", "permitId", "aci");
    require(integer(root, "deviceId") == 1);
    return new Resolution(string(root, "nonce"), operation(root.get("operation")),
        new Membership(uuid(string(m, "memberId")), integer(m, "approvalEpoch"), uuid(string(m, "signalOperationId")),
            string(m, "permitId"), uuid(string(m, "aci"))), 1, integer(root, "remainingNanos"));
  }
  private static com.fasterxml.jackson.databind.node.ObjectNode operation(Operation o) {
    return JSON.createObjectNode().put("method", o.method).put("kind", o.kind.name()).put("groupId", o.groupId)
        .put("requestId", o.requestId.toString()).put("bodySha256", o.bodySha256);
  }
  private static Operation operation(JsonNode n) {
    keys(n, "method", "kind", "groupId", "requestId", "bodySha256");
    return new Operation(string(n, "method"), Kind.valueOf(string(n, "kind")), string(n, "groupId"),
        uuid(string(n, "requestId")), string(n, "bodySha256"));
  }
  private static JsonNode tree(byte[] bytes) {
    require(bytes != null && bytes.length > 0 && bytes.length <= MAX_WIRE_BYTES);
    try { return JSON.readTree(bytes); } catch (Exception ignored) { throw invalid(); }
  }
  private static byte[] bytes(JsonNode n) {
    try { var b = JSON.writeValueAsBytes(n); require(b.length <= MAX_WIRE_BYTES); return b; }
    catch (Exception ignored) { throw invalid(); }
  }
  private static void version(JsonNode n) { require(integer(n, "version") == 1); }
  private static void keys(JsonNode n, String... names) {
    require(n != null && n.isObject()); var actual = new HashSet<String>(); n.fieldNames().forEachRemaining(actual::add);
    require(actual.equals(Set.of(names)));
  }
  private static String string(JsonNode n, String key) { var v = n.get(key); require(v != null && v.isTextual()); return v.textValue(); }
  private static long integer(JsonNode n, String key) { var v = n.get(key); require(v != null && v.isIntegralNumber() && v.canConvertToLong()); return v.longValue(); }
  public static UUID uuid(String s) {
    require(s != null && s.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")); return UUID.fromString(s);
  }
  public static byte[] binary(String s, int size) {
    require(s != null && s.length() == (size * 8 + 5) / 6 && s.matches("[A-Za-z0-9_-]+"));
    byte[] value = Base64.getUrlDecoder().decode(s); require(value.length == size && encode(value).equals(s)); return value;
  }
  public static String encode(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }
  public static String digest(byte[] b) {
    try { return encode(MessageDigest.getInstance("SHA-256").digest(b)); } catch (Exception e) { throw new AssertionError(e); }
  }
  private static void require(boolean value) { if (!value) throw invalid(); }
  private static IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid group bridge envelope"); }
}
