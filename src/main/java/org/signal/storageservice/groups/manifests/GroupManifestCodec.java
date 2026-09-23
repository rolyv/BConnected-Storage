// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.groups.manifests;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.protobuf.ByteString;
import com.google.protobuf.Message;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.signal.libsignal.zkgroup.groups.GroupPublicParams;
import org.signal.libsignal.zkgroup.groups.UuidCiphertext;
import org.signal.storageservice.storage.protos.authority.AuthoritySnapshot;
import org.signal.storageservice.storage.protos.groups.AccessControl;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.Member;

/** Standard JWS snapshot authentication. Successful verification is NEVER current authorization. */
public final class GroupManifestCodec {
  public static final String TYPE = "bconnected-group-manifest-v1";
  public static final String ISSUER = "bconnected-group-authority";
  public static final String AUDIENCE = "bconnected-owned-clients";
  public static final int MAX_ROSTER = 8000;
  public static final int MAX_NATIVE_BYTES = 8 * 1024 * 1024;
  public static final int MAX_PAYLOAD_BYTES = 4 * 1024 * 1024;
  public static final int MAX_JWS_CHARS = 6 * 1024 * 1024;
  private static final Set<String> FIELDS = Set.of("schemaVersion", "iss", "aud", "groupId",
      "publicParamsSha256", "authorityRevision", "nativeRevision", "nativeSha256", "announcementsOnly",
      "terminated", "access", "directoryListed", "roster");
  private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
      .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
      .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(8).maxStringLength(2048)
          .maxNumberLength(20).build()).build()).enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
  private final Map<String, TrustedKey> keys;

  public enum Purpose { CURRENT_RESPONSE, HISTORICAL_SNAPSHOT }
  public enum Failure { INVALID, UNTRUSTED_KEY, STALE, UNAVAILABLE }
  public static final class Rejected extends RuntimeException {
    private final Failure reason;
    Rejected(Failure reason) { super("Group manifest rejected: " + reason); this.reason = reason; }
    public Failure reason() { return reason; }
  }
  static void require(boolean value, Failure failure) { if (!value) throw new Rejected(failure); }

  /** Explicit public trust only. Retirement permits history verification, never a current response. */
  public record TrustedKey(OctetKeyPair publicKey, boolean currentResponsesAllowed) {
    public TrustedKey {
      Objects.requireNonNull(publicKey);
      require(!publicKey.isPrivate() && Curve.Ed25519.equals(publicKey.getCurve())
          && validKeyId(publicKey.getKeyID()) && publicKey.getDecodedX().length == 32
          && JWSAlgorithm.Ed25519.equals(publicKey.getAlgorithm())
          && com.nimbusds.jose.jwk.KeyUse.SIGNATURE.equals(publicKey.getKeyUse())
          && publicKey.getX509CertURL() == null && publicKey.getX509CertChain() == null, Failure.INVALID);
    }
    @Override public String toString() { return "GroupManifestTrustedKey[redacted]"; }
  }
  /** Persist all three values atomically after receiver validation; key rotation preserves payload hash. */
  public record KnownState(long revision, ByteString nativeSha256, ByteString payloadSha256) {
    public KnownState {
      require(nativeSha256 != null && payloadSha256 != null && revision >= -1 && revision <= 0xffff_ffffL
          && (revision == -1 ? nativeSha256.isEmpty() && payloadSha256.isEmpty()
              : nativeSha256.size() == 32 && payloadSha256.size() == 32), Failure.INVALID);
    }
    public static KnownState none() { return new KnownState(-1, ByteString.EMPTY, ByteString.EMPTY); }
    @Override public String toString() { return "GroupManifestKnownState[redacted]"; }
  }
  public record Envelope(ByteString nativeGroup, String compactJws) {
    public Envelope { Objects.requireNonNull(nativeGroup); Objects.requireNonNull(compactJws); }
    @Override public String toString() { return "GroupManifestEnvelope[redacted]"; }
  }
  public record RosterEntry(UUID aci, String state, Member.Role role, ByteString declaredPrincipal) {
    @Override public String toString() { return "GroupManifestRosterEntry[redacted]"; }
  }
  /** Authentication of historical bytes only; there is no admission/device proof inside this value. */
  public record VerifiedSnapshot(ByteString groupId, long revision, ByteString nativeBytes,
      ByteString nativeSha256, ByteString payloadSha256, List<RosterEntry> roster, String keyId) {
    public VerifiedSnapshot { roster = List.copyOf(roster); }
    @Override public String toString() { return "VerifiedGroupSnapshot[redacted]"; }
  }

  public GroupManifestCodec(Map<String, TrustedKey> pinnedKeys) {
    Objects.requireNonNull(pinnedKeys);
    require(!pinnedKeys.isEmpty() && pinnedKeys.size() <= 8, Failure.INVALID);
    pinnedKeys.forEach((id, key) -> require(validKeyId(id) && key != null && id.equals(key.publicKey.getKeyID()), Failure.INVALID));
    this.keys = Map.copyOf(pinnedKeys);
  }

  static boolean validKeyId(String id) { return id != null && id.matches("[A-Za-z0-9_-]{1,64}"); }
  TrustedKey currentKey(String keyId) {
    var key = keys.get(keyId);
    require(key != null && key.currentResponsesAllowed, Failure.UNTRUSTED_KEY);
    return key;
  }

  // Package-private: only GroupManifestService reads then signs authoritative state in production.
  Envelope sign(AuthoritySnapshot state, String keyId, JWSSigner signer) {
    try {
      currentKey(keyId);
      noUnknownFields(state);
      require(!state.getDirectoryListed() && state.getRosterCount() <= MAX_ROSTER, Failure.INVALID);
      var roster = state.getRosterList().stream().map(e -> new RosterEntry(UUID.fromString(e.getAci()),
          e.getState().name(), Member.Role.forNumber(e.getRole()), e.getDeclaredPrincipal()))
          .sorted(Comparator.comparing(e -> e.aci.toString())).toList();
      var group = parseNative(state.getNativeGroup());
      var payload = projection(state.getGroupId(), state.getRevision(), group, state.getNativeGroup(), roster);
      require(state.getNativeSha256().equals(hash(state.getNativeGroup())), Failure.INVALID);
      byte[] bytes = JSON.writeValueAsBytes(payload);
      require(bytes.length <= MAX_PAYLOAD_BYTES, Failure.INVALID);
      var object = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.Ed25519).keyID(keyId)
          .type(new JOSEObjectType(TYPE)).build(), new Payload(bytes));
      object.sign(signer);
      var envelope = new Envelope(state.getNativeGroup(), object.serialize());
      // Also proves that the injected signer matches the explicitly pinned public key.
      verify(envelope, state.getGroupId(), KnownState.none(), Purpose.CURRENT_RESPONSE);
      return envelope;
    } catch (Rejected failure) { throw failure; }
    catch (Exception failure) { throw new Rejected(Failure.INVALID); }
  }

  /**
   * KnownState.none() is permitted only when the caller has no saved validated state.
   * A history caller supplies the original expected group/context; it must not use this as a grant.
   */
  public VerifiedSnapshot verify(Envelope envelope, ByteString expectedGroupId, KnownState known, Purpose purpose) {
    try {
      Objects.requireNonNull(purpose); Objects.requireNonNull(known);
      require(expectedGroupId != null && expectedGroupId.size() == 32, Failure.INVALID);
      require(envelope != null && !envelope.compactJws.isEmpty() && envelope.compactJws.length() <= MAX_JWS_CHARS, Failure.INVALID);
      String[] parts = envelope.compactJws.split("\\.", 4);
      require(parts.length == 3, Failure.INVALID);
      byte[] headerBytes = decode(parts[0], 1024), payloadBytes = decode(parts[1], MAX_PAYLOAD_BYTES);
      require(decode(parts[2], 64).length == 64, Failure.INVALID);
      var header = parseJson(headerBytes);
      exact(header, Set.of("alg", "kid", "typ"));
      require(text(header, "alg").equals("Ed25519") && text(header, "typ").equals(TYPE), Failure.INVALID);
      String keyId = text(header, "kid"); require(validKeyId(keyId), Failure.INVALID);
      var key = keys.get(keyId);
      require(key != null && (purpose == Purpose.HISTORICAL_SNAPSHOT || key.currentResponsesAllowed), Failure.UNTRUSTED_KEY);
      var object = JWSObject.parse(envelope.compactJws);
      require(object.verify(new Ed25519Verifier(key.publicKey)), Failure.INVALID);
      var payload = parseJson(payloadBytes); exact(payload, FIELDS);
      require(integer(payload, "schemaVersion", 1) == 1 && text(payload, "iss").equals(ISSUER)
          && text(payload, "aud").equals(AUDIENCE), Failure.INVALID);
      var groupId = binary(payload, "groupId", 32);
      require(groupId.equals(expectedGroupId), Failure.INVALID);
      long revision = integer(payload, "authorityRevision", 0xffff_ffffL);
      require(revision >= known.revision, Failure.STALE);
      var nativeHash = binary(payload, "nativeSha256", 32);
      var payloadHash = hash(ByteString.copyFrom(payloadBytes));
      if (revision == known.revision) require(nativeHash.equals(known.nativeSha256)
          && payloadHash.equals(known.payloadSha256), Failure.STALE);
      var rosterNode = payload.get("roster");
      require(rosterNode.isArray() && !rosterNode.isEmpty() && rosterNode.size() <= MAX_ROSTER, Failure.INVALID);
      var roster = new ArrayList<RosterEntry>();
      for (var entry : rosterNode) {
        exact(entry, Set.of("aci", "state", "role", "declaredPrincipal"));
        String aciText = text(entry, "aci"); UUID aci = UUID.fromString(aciText);
        require(aci.toString().equals(aciText) && !aci.equals(new UUID(0, 0)), Failure.INVALID);
        String role = text(entry, "role");
        require(role.equals("DEFAULT") || role.equals("ADMINISTRATOR"), Failure.INVALID);
        byte[] principal = decode(text(entry, "declaredPrincipal"), 128);
        new UuidCiphertext(principal);
        roster.add(new RosterEntry(aci, text(entry, "state"), Member.Role.valueOf(role), ByteString.copyFrom(principal)));
      }
      var group = parseNative(envelope.nativeGroup);
      var expected = projection(groupId, revision, group, envelope.nativeGroup, roster);
      // Version-one serialization is schema-defined and deterministic. Consumers verify received
      // JWS bytes, never an independently reserialized generic protobuf/JSON representation.
      require(MessageDigest.isEqual(payloadBytes, JSON.writeValueAsBytes(expected)), Failure.INVALID);
      return new VerifiedSnapshot(groupId, revision, envelope.nativeGroup, nativeHash,
          payloadHash, roster, keyId);
    } catch (Rejected failure) { throw failure; }
    catch (Exception failure) { throw new Rejected(Failure.INVALID); }
  }

  private static ObjectNode projection(ByteString id, long revision, Group group, ByteString nativeBytes,
      List<RosterEntry> roster) throws Exception {
    require(id.size() == 32 && revision >= 0 && revision <= 0xffff_ffffL && roster.size() <= MAX_ROSTER
        && revision == Integer.toUnsignedLong(group.getVersion()), Failure.INVALID);
    var params = new GroupPublicParams(group.getPublicKey().toByteArray());
    require(id.equals(ByteString.copyFrom(params.getGroupIdentifier().serialize())), Failure.INVALID);
    require(group.getMembersPendingAdminApprovalCount() == 0 && group.getMembersBannedCount() == 0
        && group.getInviteLinkPassword().isEmpty(), Failure.INVALID);
    var access = group.getAccessControl();
    require(access.getAttributes() == AccessControl.AccessRequired.ADMINISTRATOR
        && access.getMembers() == AccessControl.AccessRequired.ADMINISTRATOR
        && access.getAddFromInviteLink() == AccessControl.AccessRequired.UNSATISFIABLE
        && access.getMemberLabel() == AccessControl.AccessRequired.UNKNOWN, Failure.INVALID);
    var active = new HashMap<ByteString, Member>(); var invited = new HashMap<ByteString, Member>();
    for (var member : group.getMembersList()) require(active.put(member.getUserId(), member) == null, Failure.INVALID);
    for (var pending : group.getMembersPendingProfileKeyList()) {
      require(pending.hasMember(), Failure.INVALID);
      require(invited.put(pending.getMember().getUserId(), pending.getMember()) == null, Failure.INVALID);
    }
    require(active.size() + invited.size() == roster.size(), Failure.INVALID);
    var seenPrincipals = new HashSet<ByteString>(); String prior = ""; int admins = 0;
    for (var entry : roster) {
      require(entry.aci != null && !entry.aci.equals(new UUID(0, 0)) && entry.aci.toString().compareTo(prior) > 0
          && seenPrincipals.add(entry.declaredPrincipal), Failure.INVALID);
      prior = entry.aci.toString(); new UuidCiphertext(entry.declaredPrincipal.toByteArray());
      require(entry.role == Member.Role.DEFAULT || entry.role == Member.Role.ADMINISTRATOR, Failure.INVALID);
      var member = entry.state.equals("ACTIVE") ? active.remove(entry.declaredPrincipal) : invited.remove(entry.declaredPrincipal);
      require(member != null && member.getRole() == entry.role && member.getPresentation().isEmpty(), Failure.INVALID);
      if (entry.state.equals("ACTIVE")) {
        require(!member.getProfileKey().isEmpty(), Failure.INVALID);
        if (entry.role == Member.Role.ADMINISTRATOR) admins++;
      } else {
        require(entry.state.equals("INVITED") && entry.role == Member.Role.DEFAULT && member.getProfileKey().isEmpty(), Failure.INVALID);
      }
    }
    require(active.isEmpty() && invited.isEmpty() && admins > 0, Failure.INVALID);
    var result = JSON.createObjectNode();
    result.put("schemaVersion", 1); result.put("iss", ISSUER); result.put("aud", AUDIENCE);
    result.put("groupId", encode(id)); result.put("publicParamsSha256", encode(hash(group.getPublicKey())));
    result.put("authorityRevision", revision); result.put("nativeRevision", Integer.toUnsignedLong(group.getVersion()));
    result.put("nativeSha256", encode(hash(nativeBytes))); result.put("announcementsOnly", group.getAnnouncementsOnly());
    result.put("terminated", group.getTerminated());
    var policy = result.putObject("access");
    policy.put("attributes", access.getAttributes().name()); policy.put("members", access.getMembers().name());
    policy.put("addFromInviteLink", access.getAddFromInviteLink().name()); policy.put("memberLabel", access.getMemberLabel().name());
    result.put("directoryListed", false);
    var entries = result.putArray("roster");
    for (var entry : roster) {
      var value = entries.addObject(); value.put("aci", entry.aci.toString()); value.put("state", entry.state);
      value.put("role", entry.role.name()); value.put("declaredPrincipal", encode(entry.declaredPrincipal));
    }
    return result;
  }
  private static Group parseNative(ByteString bytes) throws Exception {
    require(!bytes.isEmpty() && bytes.size() <= MAX_NATIVE_BYTES, Failure.INVALID);
    var group = Group.parseFrom(bytes); noUnknownFields(group); return group;
  }
  private static void noUnknownFields(Message message) {
    require(message.getUnknownFields().asMap().isEmpty(), Failure.INVALID);
    for (var field : message.getAllFields().entrySet()) {
      if (field.getKey().getJavaType() != com.google.protobuf.Descriptors.FieldDescriptor.JavaType.MESSAGE) continue;
      if (field.getKey().isRepeated()) for (var nested : (List<?>) field.getValue()) noUnknownFields((Message) nested);
      else noUnknownFields((Message) field.getValue());
    }
  }
  private static JsonNode parseJson(byte[] bytes) throws Exception {
    return JSON.readTree(StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString());
  }
  private static void exact(JsonNode value, Set<String> fields) {
    require(value != null && value.isObject(), Failure.INVALID);
    var names = new HashSet<String>(); value.fieldNames().forEachRemaining(names::add);
    require(names.equals(fields), Failure.INVALID);
  }
  private static String text(JsonNode object, String field) {
    var value = object.get(field); require(value != null && value.isTextual(), Failure.INVALID); return value.textValue();
  }
  private static long integer(JsonNode object, String field, long maximum) {
    var value = object.get(field);
    require(value != null && value.isIntegralNumber() && value.canConvertToLong()
        && value.longValue() >= 0 && value.longValue() <= maximum, Failure.INVALID); return value.longValue();
  }
  private static ByteString binary(JsonNode object, String field, int size) {
    byte[] decoded = decode(text(object, field), size); require(decoded.length == size, Failure.INVALID); return ByteString.copyFrom(decoded);
  }
  private static byte[] decode(String text, int maximum) {
    require(!text.isEmpty() && text.length() <= (maximum * 4L + 2) / 3 && text.matches("[A-Za-z0-9_-]+"), Failure.INVALID);
    byte[] decoded = Base64.getUrlDecoder().decode(text);
    require(decoded.length <= maximum && Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(text), Failure.INVALID);
    return decoded;
  }
  static String encode(ByteString bytes) { return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes.toByteArray()); }
  static ByteString hash(ByteString bytes) {
    try { return ByteString.copyFrom(MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray())); }
    catch (Exception impossible) { throw new IllegalStateException("SHA-256 unavailable"); }
  }
}
