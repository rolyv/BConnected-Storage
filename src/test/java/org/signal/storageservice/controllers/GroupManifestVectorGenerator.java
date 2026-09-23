// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.ByteString;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.Ed25519Signer;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import org.signal.storageservice.groups.manifests.GroupManifestCodec.*;
import org.signal.storageservice.groups.manifests.ManifestTestSupport;

/** Offline synthetic interoperability fixture. Outputs NO signing private key. Never used at runtime. */
public final class GroupManifestVectorGenerator {
  private GroupManifestVectorGenerator() {}
  public static void main(String[] args) throws Exception {
    if (args.length != 1) throw new IllegalArgumentException("One output fixture path required");
    GroupManifestCodecTest.setup();
    var json = new ObjectMapper(); var result = json.createObjectNode();
    result.put("description", "Synthetic libsignal group; public JWS signing key only; synthetic group secret for receiver decryption tests. Never production trust.");
    result.set("publicJwk", json.readTree(GroupManifestCodecTest.key.toPublicJWK().toJSONString()));
    result.put("syntheticGroupSecretParams", encode(GroupManifestCodecTest.fixture.groupSecret.serialize()));
    var state = GroupManifestCodecTest.state; var envelope = GroupManifestCodecTest.envelope;
    result.put("nativeGroup", encode(envelope.nativeGroup().toByteArray()));
    result.put("groupId", encode(state.getGroupId().toByteArray()));
    result.put("compactJws", envelope.compactJws());
    var verified = GroupManifestCodecTest.verify(envelope);
    result.put("nativeSha256", encode(verified.nativeSha256().toByteArray()));
    result.put("payloadSha256", encode(verified.payloadSha256().toByteArray()));
    result.put("canonicalPayload", JWSObject.parse(envelope.compactJws()).getPayload().toString());
    var acis = result.putArray("expectedDecryptedAcis");
    state.getRosterList().forEach(e -> acis.add(e.getAci()));
    var different = state.toBuilder().setRoster(0, state.getRoster(0).toBuilder().setAci(UUID.randomUUID().toString())).build();
    result.put("sameRevisionDifferentClearRosterJws", ManifestTestSupport.sign(GroupManifestCodecTest.codec,
        different, GroupManifestCodecTest.key.getKeyID(), new Ed25519Signer(GroupManifestCodecTest.key)).compactJws());
    // A valid signature is insufficient: this changes the declared ACI without changing its encrypted principal.
    result.put("wrongSigningPublicKey", encode(GroupManifestCodecTest.next.getDecodedX()));
    json.writerWithDefaultPrettyPrinter().writeValue(Path.of(args[0]).toFile(), result);
  }
  private static String encode(byte[] value) { return Base64.getUrlEncoder().withoutPadding().encodeToString(value); }
}
