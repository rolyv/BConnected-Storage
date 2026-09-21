// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.controllers;

import com.google.protobuf.ByteString;
import io.dropwizard.auth.basic.BasicCredentials;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.signal.libsignal.protocol.ServiceId;
import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.protocol.ServiceId.Pni;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.auth.ClientZkAuthOperations;
import org.signal.libsignal.zkgroup.auth.ServerZkAuthOperations;
import org.signal.libsignal.zkgroup.groups.ClientZkGroupCipher;
import org.signal.libsignal.zkgroup.groups.GroupSecretParams;
import org.signal.libsignal.zkgroup.groupsend.GroupSendDerivedKeyPair;
import org.signal.libsignal.zkgroup.groupsend.GroupSendEndorsementsResponse;
import org.signal.libsignal.zkgroup.profiles.ClientZkProfileOperations;
import org.signal.libsignal.zkgroup.profiles.ProfileKey;
import org.signal.libsignal.zkgroup.profiles.ServerZkProfileOperations;
import org.signal.storageservice.auth.GroupUser;
import org.signal.storageservice.auth.GroupUserAuthenticator;
import org.signal.storageservice.storage.protos.groups.AccessControl;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupAttributeBlob;
import org.signal.storageservice.storage.protos.groups.GroupResponse;
import org.signal.storageservice.storage.protos.groups.Member;

/** Fresh, local-only cryptographic identities. These are not registered Signal user accounts. */
final class SyntheticGroupFixture {
  final ServerSecretParams server = ServerSecretParams.generate();
  final GroupSecretParams groupSecret = GroupSecretParams.generate();
  final ClientZkGroupCipher cipher = new ClientZkGroupCipher(groupSecret);
  final Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
  private final Instant redemption = now.truncatedTo(ChronoUnit.DAYS);
  final List<ServiceId> identities;
  final Group submitted;
  final long generationMs;

  SyntheticGroupFixture(int count) throws Exception {
    if (count < 2 || count > 10_000) throw new IllegalArgumentException("Invalid synthetic population");
    long start = System.nanoTime();
    var clientProfiles = new ClientZkProfileOperations(server.getPublicParams());
    var serverProfiles = new ServerZkProfileOperations(server);
    var random = new SecureRandom();
    var members = new ArrayList<ServiceId>();
    var request = Group.newBuilder()
        .setPublicKey(ByteString.copyFrom(groupSecret.getPublicParams().serialize()))
        .setTitle(encryptedTitle("Synthetic alumni announcements"))
        .setAnnouncementsOnly(true)
        .setAccessControl(AccessControl.newBuilder()
            .setMembers(AccessControl.AccessRequired.ADMINISTRATOR)
            .setAttributes(AccessControl.AccessRequired.ADMINISTRATOR)
            .setAddFromInviteLink(AccessControl.AccessRequired.UNSATISFIABLE));
    for (int index = 0; index < count; index++) {
      var aci = new Aci(UUID.randomUUID());
      members.add(aci);
      byte[] profileBytes = new byte[32];
      random.nextBytes(profileBytes);
      var key = new ProfileKey(profileBytes);
      var context = clientProfiles.createProfileKeyCredentialRequestContext(aci, key);
      var issued = serverProfiles.issueExpiringProfileKeyCredential(context.getRequest(), aci,
          key.getCommitment(aci), redemption.plus(2, ChronoUnit.DAYS));
      var credential = clientProfiles.receiveExpiringProfileKeyCredential(context, issued, now);
      var presentation = clientProfiles.createProfileKeyCredentialPresentation(groupSecret, credential);
      request.addMembers(Member.newBuilder()
          .setRole(index == 0 ? Member.Role.ADMINISTRATOR : Member.Role.DEFAULT)
          .setPresentation(ByteString.copyFrom(presentation.serialize())));
    }
    identities = List.copyOf(members);
    submitted = Group.parseFrom(request.build().toByteArray());
    generationMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
  }

  private BasicCredentials credentials(int index) throws Exception {
    var aci = (Aci) identities.get(index);
    var pni = new Pni(UUID.randomUUID());
    var issued = new ServerZkAuthOperations(server).issueAuthCredentialWithPniZkc(aci, pni, redemption);
    var client = new ClientZkAuthOperations(server.getPublicParams());
    var credential = client.receiveAuthCredentialWithPniAsServiceId(aci, pni, redemption.getEpochSecond(), issued);
    var presentation = client.createAuthCredentialPresentation(groupSecret, credential);
    return new BasicCredentials(HexFormat.of().formatHex(groupSecret.getPublicParams().serialize()),
        HexFormat.of().formatHex(presentation.serialize()));
  }

  GroupUser authenticatedUser(int index) throws Exception {
    return new GroupUserAuthenticator(new ServerZkAuthOperations(server)).authenticate(credentials(index)).orElseThrow();
  }

  String authorization(int index) throws Exception {
    var credentials = credentials(index);
    return "Basic " + Base64.getEncoder().encodeToString(
        (credentials.getUsername() + ":" + credentials.getPassword()).getBytes(StandardCharsets.US_ASCII));
  }

  ByteString encryptedTitle(String title) throws Exception {
    return ByteString.copyFrom(cipher.encryptBlob(GroupAttributeBlob.newBuilder().setTitle(title).build().toByteArray()));
  }

  void verifyEndorsements(GroupResponse group) throws Exception {
    var response = new GroupSendEndorsementsResponse(group.getGroupSendEndorsementsResponse().toByteArray());
    var endorsements = response.receive(identities, (Aci) identities.getFirst(), now, groupSecret, server.getPublicParams());
    var token = endorsements.combinedEndorsement().toFullToken(groupSecret, response.getExpiration());
    token.verify(identities.subList(1, identities.size()), now,
        GroupSendDerivedKeyPair.forExpiration(response.getExpiration(), server));
  }

  @Override public String toString() { return "SyntheticGroupFixture[redacted]"; }
}
