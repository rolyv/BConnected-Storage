// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.controllers;

import static org.assertj.core.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.protobuf.ByteString;
import com.google.protobuf.UnknownFieldSet;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.zkgroup.profiles.ServerZkProfileOperations;
import org.signal.storageservice.configuration.GroupConfiguration;
import org.signal.storageservice.groups.GroupValidator;
import org.signal.storageservice.groups.manifests.GroupManifestCodec;
import org.signal.storageservice.groups.manifests.GroupManifestCodec.*;
import org.signal.storageservice.groups.manifests.ManifestTestSupport;
import org.signal.storageservice.storage.protos.authority.AuthorityRosterEntry;
import org.signal.storageservice.storage.protos.authority.AuthoritySnapshot;
import org.signal.storageservice.storage.protos.groups.*;

class GroupManifestCodecTest {
  static SyntheticGroupFixture fixture;
  static OctetKeyPair key, next;
  static AuthoritySnapshot state;
  static GroupManifestCodec codec;
  static Envelope envelope;
  static final ObjectMapper JSON = new ObjectMapper();
  @BeforeAll static void setup() throws Exception {
    fixture = new SyntheticGroupFixture(3);
    key = key("group-manifest-test-1"); next = key("group-manifest-test-2");
    codec = codec(Map.of(key.getKeyID(), new TrustedKey(key.toPublicJWK(), true)));
    var validator = new GroupValidator(new ServerZkProfileOperations(fixture.server),
        new GroupConfiguration(8000, 1024, 8192, new byte[32], null, null));
    var group = fixture.submitted.toBuilder().clearMembers(); var roster = new ArrayList<AuthorityRosterEntry>();
    for (int i = 0; i < 3; i++) {
      var member = validator.validateMember(fixture.submitted, fixture.submitted.getMembers(i));
      group.addMembers(member);
      roster.add(AuthorityRosterEntry.newBuilder().setAci(((Aci) fixture.identities.get(i)).getRawUUID().toString())
          .setDeclaredPrincipal(member.getUserId()).setRole(member.getRoleValue()).setState(AuthorityRosterEntry.State.ACTIVE)
          .setEnrollmentId(UUID.randomUUID().toString()).setApprovalEpoch(7).build());
    }
    state = state(group.build(), roster);
    envelope = ManifestTestSupport.sign(codec, state, key.getKeyID(), new Ed25519Signer(key));
  }
  static OctetKeyPair key(String id) throws Exception {
    return new OctetKeyPairGenerator(Curve.Ed25519).keyID(id).algorithm(JWSAlgorithm.Ed25519).keyUse(KeyUse.SIGNATURE).generate();
  }
  static GroupManifestCodec codec(Map<String, TrustedKey> keys) { return new GroupManifestCodec(keys); }
  static ByteString hash(ByteString bytes) throws Exception { return ByteString.copyFrom(MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray())); }
  static AuthoritySnapshot state(Group group, List<AuthorityRosterEntry> roster) throws Exception {
    return AuthoritySnapshot.newBuilder().setGroupId(ByteString.copyFrom(fixture.groupSecret.getPublicParams().getGroupIdentifier().serialize()))
        .setRevision(Integer.toUnsignedLong(group.getVersion())).setCreatorAci(((Aci) fixture.identities.getFirst()).getRawUUID().toString())
        .setNativeGroup(group.toByteString()).setNativeSha256(hash(group.toByteString()))
        .addAllRoster(roster.stream().sorted(Comparator.comparing(AuthorityRosterEntry::getAci)).toList()).build();
  }
  static VerifiedSnapshot verify(Envelope value) { return codec.verify(value, state.getGroupId(), KnownState.none(), Purpose.CURRENT_RESPONSE); }
  static ObjectNode payload() throws Exception { return (ObjectNode) JSON.readTree(JWSObject.parse(envelope.compactJws()).getPayload().toBytes()); }
  static Envelope resign(ObjectNode payload) throws Exception { return rawSign("{\"alg\":\"Ed25519\",\"kid\":\""+key.getKeyID()+"\",\"typ\":\""+GroupManifestCodec.TYPE+"\"}", JSON.writeValueAsBytes(payload), envelope.nativeGroup()); }
  static Envelope rawSign(String header, byte[] payload, ByteString nativeBytes) throws Exception {
    var base64 = Base64.getUrlEncoder().withoutPadding();
    String input = base64.encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "." + base64.encodeToString(payload);
    var signature = new Ed25519Signer(key).sign(new JWSHeader.Builder(JWSAlgorithm.Ed25519).build(), input.getBytes(StandardCharsets.US_ASCII));
    return new Envelope(nativeBytes, input + "." + signature);
  }
  static void invalid(Envelope value) { assertThatThrownBy(() -> verify(value)).isInstanceOf(Rejected.class); }
  @Test void standardJwsRoundTripPreservesExactNativeHashAndOmitsInternalAdmissionBindings() throws Exception {
    var verified = verify(envelope);
    assertThat(verified.groupId()).isEqualTo(state.getGroupId()); assertThat(verified.nativeBytes()).isEqualTo(state.getNativeGroup());
    assertThat(verified.nativeSha256()).isEqualTo(state.getNativeSha256()); assertThat(verified.roster()).hasSize(3);
    String payload = JWSObject.parse(envelope.compactJws()).getPayload().toString();
    assertThat(payload).doesNotContain("enrollment", "approvalEpoch", "memberId", "permit", "creator");
    assertThat(JWSObject.parse(envelope.compactJws()).getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.Ed25519);
    // Ed25519 has deterministic signatures: retries preserve exact bytes and payload identity.
    assertThat(ManifestTestSupport.sign(codec, state, key.getKeyID(), new Ed25519Signer(key))).isEqualTo(envelope);
    assertThat(envelope.toString()).doesNotContain(envelope.compactJws());
    assertThat(verified.toString()).doesNotContain(verified.roster().getFirst().aci().toString());
  }
  @ParameterizedTest @ValueSource(ints = {0, 1, 2})
  void alteredCompactPartNeverVerifies(int part) {
    var parts = envelope.compactJws().split("\\."); String value = parts[part];
    parts[part] = (value.charAt(0) == 'A' ? "B" : "A") + value.substring(1);
    invalid(new Envelope(envelope.nativeGroup(), String.join(".", parts)));
  }
  @ParameterizedTest @ValueSource(strings = {"version", "issuer", "audience", "group", "publicParams", "nativeHash", "revision", "float", "overflow", "nativeVersion", "policy", "terminated", "access", "directory", "unknown", "missing", "duplicateAci", "duplicatePrincipal", "role", "status", "extraMember", "missingMember", "order", "unknownRoster", "aciCase", "principal"})
  void validSignatureDoesNotBypassExactAuthoritySchema(String scenario) throws Exception {
    var p = payload(); var first = (ObjectNode) p.withArray("roster").get(0); var second = (ObjectNode) p.withArray("roster").get(1);
    switch (scenario) {
      case "version" -> p.put("schemaVersion", 2);
      case "issuer" -> p.put("iss", "untrusted");
      case "audience" -> p.put("aud", "bconnected-signal-registration");
      case "group" -> p.put("groupId", Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]));
      case "publicParams" -> p.put("publicParamsSha256", Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]));
      case "nativeHash" -> p.put("nativeSha256", Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]));
      case "revision" -> p.put("authorityRevision", 1);
      case "float" -> p.put("authorityRevision", 0.0);
      case "overflow" -> p.put("authorityRevision", new java.math.BigInteger("18446744073709551615"));
      case "nativeVersion" -> p.put("nativeRevision", "0");
      case "policy" -> p.put("announcementsOnly", !p.get("announcementsOnly").booleanValue());
      case "terminated" -> p.put("terminated", true);
      case "access" -> ((ObjectNode)p.get("access")).put("members", "MEMBER");
      case "directory" -> p.put("directoryListed", true);
      case "unknown" -> p.put("futurePrivilege", true);
      case "missing" -> p.remove("access");
      case "duplicateAci" -> second.set("aci", first.get("aci"));
      case "duplicatePrincipal" -> second.set("declaredPrincipal", first.get("declaredPrincipal"));
      case "role" -> first.put("role", "UNKNOWN");
      case "status" -> first.put("state", "CONSENTED");
      case "extraMember" -> p.withArray("roster").add(first.deepCopy());
      case "missingMember" -> p.withArray("roster").remove(0);
      case "order" -> { p.withArray("roster").set(0, second); p.withArray("roster").set(1, first); }
      case "unknownRoster" -> first.put("approved", true);
      case "aciCase" -> first.put("aci", first.get("aci").textValue().toUpperCase(java.util.Locale.ROOT));
      case "principal" -> first.put("declaredPrincipal", "AA");
    }
    invalid(resign(p));
  }
  @ParameterizedTest @ValueSource(strings = {"duplicatePayload", "escapedDuplicate", "duplicateHeader", "unknownHeader", "remoteKey", "wrongType", "wrongAlg", "unknownKey", "malformedUtf8", "trailingJson", "whitespace", "deepJson"})
  void malformedOrAmbiguousSignedJsonIsRejected(String scenario) throws Exception {
    String header = "{\"alg\":\"Ed25519\",\"kid\":\""+key.getKeyID()+"\",\"typ\":\""+GroupManifestCodec.TYPE+"\"}";
    String content = JSON.writeValueAsString(payload()); byte[] bytes;
    switch (scenario) {
      case "duplicatePayload" -> content = content.replaceFirst("\\{", "{\"schemaVersion\":1,");
      case "escapedDuplicate" -> content = content.replaceFirst("\\{", java.util.regex.Matcher.quoteReplacement("{\"schema\\u0056ersion\":1,"));
      case "duplicateHeader" -> header = header.replaceFirst("\\{", "{\"alg\":\"Ed25519\",");
      case "unknownHeader" -> header = header.replaceFirst("\\{", "{\"crit\":[],");
      case "remoteKey" -> header = header.replaceFirst("\\{", "{\"jku\":\"https://example.invalid/keys\",");
      case "wrongType" -> header = header.replace(GroupManifestCodec.TYPE, "bconnected-admission-v1");
      case "wrongAlg" -> header = header.replace("Ed25519", "EdDSA");
      case "unknownKey" -> header = header.replace(key.getKeyID(), "unknown-key");
      case "malformedUtf8" -> { invalid(rawSign(header, new byte[]{(byte)0xc3, (byte)0x28}, envelope.nativeGroup())); return; }
      case "trailingJson" -> content += "{}";
      case "whitespace" -> content = " " + content;
      case "deepJson" -> content = "[".repeat(20) + content + "]".repeat(20);
    }
    bytes = content.getBytes(StandardCharsets.UTF_8); invalid(rawSign(header, bytes, envelope.nativeGroup()));
  }
  @Test void nativeByteTamperingUnknownFieldsAndSnapshotMismatchFailClosed() throws Exception {
    assertThatThrownBy(() -> ManifestTestSupport.sign(codec, state.toBuilder().setDirectoryListed(true).build(), key.getKeyID(), new Ed25519Signer(key))).isInstanceOf(Rejected.class);
    var nativeGroup = Group.parseFrom(envelope.nativeGroup());
    invalid(new Envelope(nativeGroup.toBuilder().setTitle(ByteString.copyFromUtf8("changed")).build().toByteString(), envelope.compactJws()));
    var malformed = nativeGroup.toBuilder().setUnknownFields(UnknownFieldSet.newBuilder().addField(99, UnknownFieldSet.Field.newBuilder().addVarint(1).build()).build()).build();
    assertThatThrownBy(() -> ManifestTestSupport.sign(codec, state(malformed, state.getRosterList()), key.getKeyID(), new Ed25519Signer(key))).isInstanceOf(Rejected.class);
    assertThatThrownBy(() -> ManifestTestSupport.sign(codec, state.toBuilder().setNativeSha256(ByteString.copyFrom(new byte[32])).build(), key.getKeyID(), new Ed25519Signer(key))).isInstanceOf(Rejected.class);
  }
  @Test void explicitRotationPinsSeparateHistoricalVerificationFromCurrentResponses() throws Exception {
    var rotated = codec(Map.of(key.getKeyID(), new TrustedKey(key.toPublicJWK(), false), next.getKeyID(), new TrustedKey(next.toPublicJWK(), true)));
    assertThat(rotated.verify(envelope, state.getGroupId(), KnownState.none(), Purpose.HISTORICAL_SNAPSHOT).nativeBytes()).isEqualTo(state.getNativeGroup());
    assertThatThrownBy(() -> rotated.verify(envelope, state.getGroupId(), KnownState.none(), Purpose.CURRENT_RESPONSE)).isInstanceOf(Rejected.class);
    var nextEnvelope = ManifestTestSupport.sign(rotated, state, next.getKeyID(), new Ed25519Signer(next));
    assertThat(rotated.verify(nextEnvelope, state.getGroupId(), KnownState.none(), Purpose.CURRENT_RESPONSE).payloadSha256()).isEqualTo(verify(envelope).payloadSha256());
    invalid(nextEnvelope);
    assertThatThrownBy(() -> new TrustedKey(key, true)).isInstanceOf(Rejected.class);
    assertThatThrownBy(() -> codec(Map.of())).isInstanceOf(Rejected.class);
    assertThatThrownBy(() -> codec(Map.of("mismatched", new TrustedKey(key.toPublicJWK(), true)))).isInstanceOf(Rejected.class);
    assertThatThrownBy(() -> ManifestTestSupport.sign(codec, state, key.getKeyID(), new Ed25519Signer(next))).isInstanceOf(Rejected.class);
  }
  @Test void revisionFloorAndSameRevisionDivergenceCannotBeHiddenByValidSignature() throws Exception {
    assertThatThrownBy(() -> codec.verify(envelope, state.getGroupId(), new KnownState(1, state.getNativeSha256(), verify(envelope).payloadSha256()), Purpose.CURRENT_RESPONSE)).isInstanceOf(Rejected.class);
    assertThatThrownBy(() -> codec.verify(envelope, state.getGroupId(), new KnownState(0, ByteString.copyFrom(new byte[32]), verify(envelope).payloadSha256()), Purpose.CURRENT_RESPONSE)).isInstanceOf(Rejected.class);
    assertThat(codec.verify(envelope, state.getGroupId(), new KnownState(0, state.getNativeSha256(), verify(envelope).payloadSha256()), Purpose.CURRENT_RESPONSE).revision()).isZero();
  }
  @Test void sameRevisionClearIdentityChangeIsDivergenceEvenWhenNativeBytesAreUnchanged() throws Exception {
    var roster = new ArrayList<>(state.getRosterList());
    roster.set(0, roster.get(0).toBuilder().setAci(UUID.randomUUID().toString()).build());
    var changed = state.toBuilder().clearRoster().addAllRoster(roster).build();
    var signed = ManifestTestSupport.sign(codec, changed, key.getKeyID(), new Ed25519Signer(key));
    var known = new KnownState(0, state.getNativeSha256(), verify(envelope).payloadSha256());
    assertThatThrownBy(() -> codec.verify(signed, state.getGroupId(), known, Purpose.CURRENT_RESPONSE))
        .isInstanceOf(Rejected.class).satisfies(e -> assertThat(((Rejected)e).reason()).isEqualTo(Failure.STALE));
  }
  @Test void sizeAndEncodingBoundsRejectBeforeUnboundedParsing() throws Exception {
    invalid(new Envelope(ByteString.copyFrom(new byte[GroupManifestCodec.MAX_NATIVE_BYTES + 1]), envelope.compactJws()));
    invalid(new Envelope(envelope.nativeGroup(), "A".repeat(GroupManifestCodec.MAX_JWS_CHARS + 1)));
    invalid(new Envelope(envelope.nativeGroup(), ".".repeat(GroupManifestCodec.MAX_JWS_CHARS)));
    invalid(new Envelope(envelope.nativeGroup(), envelope.compactJws() + "="));
    invalid(new Envelope(envelope.nativeGroup(), envelope.compactJws().replaceFirst("\\.", "..")));
    invalid(new Envelope(envelope.nativeGroup(), envelope.compactJws().substring(0, envelope.compactJws().lastIndexOf('.')) + "."));
    var p = payload(); p.put("nativeSha256", "A".repeat(2049)); invalid(resign(p));
    p = payload(); var roster = p.withArray("roster"); var sample = roster.get(0).deepCopy();
    while (roster.size() <= GroupManifestCodec.MAX_ROSTER) roster.add(sample.deepCopy()); invalid(resign(p));
  }
  @Test void committedInteropFixtureVerifiesAndDecryptsEveryDeclaredAci() throws Exception {
    var vector = JSON.readTree(java.nio.file.Path.of("bconnected/test-vectors/group-manifest-v1.json").toFile());
    var publicKey = OctetKeyPair.parse(vector.get("publicJwk").toString());
    assertThat(publicKey.isPrivate()).isFalse();
    var fixtureCodec = codec(Map.of(publicKey.getKeyID(), new TrustedKey(publicKey, true)));
    var decoder = Base64.getUrlDecoder();
    var nativeBytes = ByteString.copyFrom(decoder.decode(vector.get("nativeGroup").textValue()));
    var groupId = ByteString.copyFrom(decoder.decode(vector.get("groupId").textValue()));
    var example = new Envelope(nativeBytes, vector.get("compactJws").textValue());
    var actual = fixtureCodec.verify(example, groupId, KnownState.none(), Purpose.CURRENT_RESPONSE);
    assertThat(Base64.getUrlEncoder().withoutPadding().encodeToString(actual.nativeSha256().toByteArray())).isEqualTo(vector.get("nativeSha256").textValue());
    assertThat(Base64.getUrlEncoder().withoutPadding().encodeToString(actual.payloadSha256().toByteArray())).isEqualTo(vector.get("payloadSha256").textValue());
    assertThat(JWSObject.parse(example.compactJws()).getPayload().toString()).isEqualTo(vector.get("canonicalPayload").textValue());
    var secret = new org.signal.libsignal.zkgroup.groups.GroupSecretParams(decoder.decode(vector.get("syntheticGroupSecretParams").textValue()));
    var cipher = new org.signal.libsignal.zkgroup.groups.ClientZkGroupCipher(secret);
    for (var entry : actual.roster()) {
      var decrypted = cipher.decrypt(new org.signal.libsignal.zkgroup.groups.UuidCiphertext(entry.declaredPrincipal().toByteArray()));
      assertThat(decrypted).isEqualTo(new Aci(entry.aci()));
    }
    var changed = new Envelope(nativeBytes, vector.get("sameRevisionDifferentClearRosterJws").textValue());
    assertThatThrownBy(() -> fixtureCodec.verify(changed, groupId, new KnownState(actual.revision(), actual.nativeSha256(), actual.payloadSha256()), Purpose.CURRENT_RESPONSE)).isInstanceOf(Rejected.class);
    // First-use structural signature verification cannot establish clear-to-ciphertext equivalence.
    var firstUse = fixtureCodec.verify(changed, groupId, KnownState.none(), Purpose.CURRENT_RESPONSE);
    assertThat(firstUse.roster()).anySatisfy(entry -> {
      try { assertThat(cipher.decrypt(new org.signal.libsignal.zkgroup.groups.UuidCiphertext(entry.declaredPrincipal().toByteArray()))).isNotEqualTo(new Aci(entry.aci())); }
      catch (Exception invalid) { throw new AssertionError(invalid); }
    });
  }
  @Test void eightThousandDistinctEncryptedPrincipalsFitBoundedManifest() throws Exception {
    var nativeGroup = Group.parseFrom(state.getNativeGroup()); var builder = nativeGroup.toBuilder().clearMembers();
    var entries = new ArrayList<AuthorityRosterEntry>();
    for (int i = 0; i < 8000; i++) {
      var aci = new Aci(UUID.randomUUID()); var principal = ByteString.copyFrom(fixture.cipher.encrypt(aci).serialize());
      var role = i == 0 ? Member.Role.ADMINISTRATOR : Member.Role.DEFAULT;
      // Capacity concerns the signed roster projection, not profile-credential enrollment throughput.
      builder.addMembers(nativeGroup.getMembers(0).toBuilder().setUserId(principal).setRole(role));
      entries.add(state.getRoster(0).toBuilder().setAci(aci.getRawUUID().toString()).setDeclaredPrincipal(principal).setRole(role.getNumber()).build());
    }
    var large = state(builder.build(), entries);
    var signed = ManifestTestSupport.sign(codec, large, key.getKeyID(), new Ed25519Signer(key));
    assertThat(codec.verify(signed, large.getGroupId(), KnownState.none(), Purpose.CURRENT_RESPONSE).roster()).hasSize(8000);
    assertThat(signed.compactJws().length()).isLessThan(GroupManifestCodec.MAX_JWS_CHARS);
  }
}
