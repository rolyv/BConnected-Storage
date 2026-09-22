// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.avatars;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.google.cloud.storage.*;
import com.google.protobuf.ByteString;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.util.Base64;
import java.util.HexFormat;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class GcsGroupAvatarStorageTest {
  static final String BUCKET = "bconnected-group-avatars-test";
  static final String OBJECT = "AAAAAAAAAAAAAAAAAAAAAA";
  final ByteString group = ByteString.copyFrom(new byte[32]);
  Storage storage;
  GcsGroupAvatarStorage avatars;
  java.security.KeyPair key;
  @BeforeEach void setup() throws Exception {
    var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); key = generator.generateKeyPair();
    var signer = ServiceAccountCredentials.newBuilder().setClientEmail("avatar-test@fixture.iam.gserviceaccount.com")
        .setPrivateKey(key.getPrivate()).setPrivateKeyId("synthetic-key").setClientId("fixture").build();
    // Real SDK signing with a local synthetic RSA key. No ADC, IAM request or object upload.
    storage = spy(StorageOptions.newBuilder().setProjectId("fixture").setCredentials(signer).build().getService());
    avatars = new GcsGroupAvatarStorage(storage, BUCKET, signer, Clock.systemUTC());
  }
  @Test void uploadUsesExactGroupObjectPrivateScopeSizeAndVerifiableSdkSignature() throws Exception {
    var form = avatars.upload(group);
    assertThat(form.getKey()).startsWith("groups/" + Base64.getUrlEncoder().withoutPadding().encodeToString(group.toByteArray()) + "/");
    assertThat(form.getUploadUrl()).isEqualTo("https://storage.googleapis.com/" + BUCKET + "/");
    assertThat(form.getAcl()).isEmpty(); assertThat(form.getAlgorithm()).isEqualTo("GOOG4-RSA-SHA256");
    var document = new ObjectMapper().readTree(Base64.getDecoder().decode(form.getPolicy()));
    var conditions = document.required("conditions").toString();
    assertThat(conditions).contains(BUCKET, form.getKey(), "application/octet-stream", "[\"content-length-range\",1,3145728]")
        .doesNotContain("acl", "public-read", "starts-with");
    var verify = Signature.getInstance("SHA256withRSA"); verify.initVerify(key.getPublic());
    verify.update(form.getPolicy().getBytes(java.nio.charset.StandardCharsets.UTF_8));
    assertThat(verify.verify(HexFormat.of().parseHex(form.getSignature()))).isTrue();
    assertThat(form.getExpiresAt()).isBetween(Clock.systemUTC().instant().getEpochSecond() + 290,
        Clock.systemUTC().instant().getEpochSecond() + 301);
    assertThat(avatars.upload(group).getKey()).isNotEqualTo(form.getKey());
  }
  @Test void downloadPinsGenerationAndBoundedExpiryWithoutPublicAccess() {
    var object = mock(Blob.class);
    when(object.getGeneration()).thenReturn(42L); when(object.getSize()).thenReturn(128L);
    doReturn(object).when(storage).get(BlobId.of(BUCKET, GroupAvatarStorage.key(group, OBJECT)));
    var result = avatars.download(group, OBJECT);
    assertThat(result.getUrl()).startsWith("https://storage.googleapis.com/" + BUCKET + "/groups/")
        .contains("generation=42", "X-Goog-Expires=300", "X-Goog-Algorithm=GOOG4-RSA-SHA256");
    assertThat(result.getContentLength()).isEqualTo(128);
  }
  @Test void missingObjectDoesNotMintCapability() {
    doReturn(null).when(storage).get(BlobId.of(BUCKET, GroupAvatarStorage.key(group, OBJECT)));
    assertThatThrownBy(() -> avatars.download(group, OBJECT)).isInstanceOf(jakarta.ws.rs.NotFoundException.class);
  }
  @ParameterizedTest @ValueSource(longs = {0, -1, 3145729})
  void badObjectSizeCannotBecomeDownloadCapability(long size) {
    var object = mock(Blob.class); when(object.getGeneration()).thenReturn(42L); when(object.getSize()).thenReturn(size);
    doReturn(object).when(storage).get(BlobId.of(BUCKET, GroupAvatarStorage.key(group, OBJECT)));
    assertThatThrownBy(() -> avatars.download(group, OBJECT)).isInstanceOf(IllegalStateException.class);
  }
  @ParameterizedTest @ValueSource(strings = {"../other", "AAAAAAAAAAAAAAAAAAAAAB", "AAAAAAAAAAAAAAAAAAAAAA==", "https://other/object", "groups/other/object"})
  void malformedOrNonCanonicalObjectIsRejectedBeforeStorage(String object) {
    assertThatThrownBy(() -> avatars.download(group, object)).isInstanceOf(IllegalArgumentException.class);
    verify(storage, never()).get(any(BlobId.class));
  }
}
