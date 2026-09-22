// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.avatars;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.auth.ServiceAccountSigner;
import com.google.cloud.storage.*;
import com.google.protobuf.ByteString;
import jakarta.ws.rs.NotFoundException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.signal.storageservice.storage.protos.groups.AvatarDownloadAttributes;
import org.signal.storageservice.storage.protos.groups.AvatarUploadAttributes;

/** SDK V4 signing with IAM signBlob; short-lived bearer capabilities, never public object ACLs. */
public final class GcsGroupAvatarStorage implements GroupAvatarStorage, AutoCloseable {
  public static final int VALIDITY_SECONDS = 300;
  private static final DateTimeFormatter SIGNING_DATE = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
      .withZone(ZoneOffset.UTC);
  private final Storage storage;
  private final String bucket;
  private final ServiceAccountSigner signer;
  private final Clock clock;

  public GcsGroupAvatarStorage(Storage storage, String bucket, ServiceAccountSigner signer, Clock clock) {
    this.storage = java.util.Objects.requireNonNull(storage);
    this.bucket = java.util.Objects.requireNonNull(bucket);
    this.signer = java.util.Objects.requireNonNull(signer);
    this.clock = java.util.Objects.requireNonNull(clock);
  }

  @Override public AvatarUploadAttributes upload(ByteString groupId) {
    byte[] random = new byte[16]; new SecureRandom().nextBytes(random);
    String key = GroupAvatarStorage.key(groupId, Base64.getUrlEncoder().withoutPadding().encodeToString(random));
    var fields = PostPolicyV4.PostFieldsV4.newBuilder().setContentType("application/octet-stream").build();
    var conditions = PostPolicyV4.PostConditionsV4.newBuilder().addContentLengthRangeCondition(1, MAX_CONTENT_LENGTH).build();
    var policy = storage.generateSignedPostPolicyV4(BlobInfo.newBuilder(bucket, key).build(), VALIDITY_SECONDS,
        TimeUnit.SECONDS, fields, conditions, Storage.PostPolicyV4Option.signWith(signer), Storage.PostPolicyV4Option.withPathStyle());
    URI endpoint = URI.create(policy.getUrl());
    requireEndpoint(endpoint, "/" + bucket + "/");
    if (endpoint.getRawQuery() != null) throw new IllegalStateException("Unexpected upload query");
    var values = policy.getFields();
    if (!key.equals(values.get("key")) || !"GOOG4-RSA-SHA256".equals(values.get("x-goog-algorithm"))
        || values.containsKey("acl") || !"application/octet-stream".equals(values.get("content-type")))
      throw new IllegalStateException("Unexpected upload policy scope");
    final Instant expires;
    try { expires = Instant.parse(new ObjectMapper().readTree(Base64.getDecoder().decode(values.get("policy"))).required("expiration").textValue()); }
    catch (Exception ignored) { throw new IllegalStateException("Invalid upload policy expiry"); }
    requireExpiry(expires);
    return AvatarUploadAttributes.newBuilder().setKey(key).setAcl("")
        .setAlgorithm(values.get("x-goog-algorithm")).setCredential(values.get("x-goog-credential"))
        .setDate(values.get("x-goog-date")).setPolicy(values.get("policy")).setSignature(values.get("x-goog-signature"))
        .setUploadUrl(endpoint.toASCIIString()).setExpiresAt(expires.getEpochSecond()).setMaxContentLength(MAX_CONTENT_LENGTH).build();
  }

  @Override public AvatarDownloadAttributes download(ByteString groupId, String objectId) {
    String key = GroupAvatarStorage.key(groupId, objectId);
    final Blob object;
    try { object = storage.get(BlobId.of(bucket, key)); }
    catch (StorageException failure) { if (failure.getCode() == 404) throw new NotFoundException(); throw failure; }
    if (object == null) throw new NotFoundException();
    if (object.getGeneration() == null || object.getGeneration() <= 0 || object.getSize() == null
        || object.getSize() < 1 || object.getSize() > MAX_CONTENT_LENGTH)
      throw new IllegalStateException("Invalid avatar metadata");
    var url = URI.create(storage.signUrl(BlobInfo.newBuilder(bucket, key).build(), VALIDITY_SECONDS, TimeUnit.SECONDS,
        Storage.SignUrlOption.withV4Signature(), Storage.SignUrlOption.httpMethod(HttpMethod.GET),
        Storage.SignUrlOption.withPathStyle(), Storage.SignUrlOption.signWith(signer),
        Storage.SignUrlOption.withQueryParams(Map.of("generation", object.getGeneration().toString()))).toString());
    requireEndpoint(url, "/" + bucket + "/" + key);
    Map<String, String> query = new HashMap<>();
    for (String field : java.util.Objects.requireNonNull(url.getRawQuery()).split("&")) {
      var pair = field.split("=", 2);
      if (pair.length != 2 || query.put(URLDecoder.decode(pair[0], StandardCharsets.UTF_8),
          URLDecoder.decode(pair[1], StandardCharsets.UTF_8)) != null) throw new IllegalStateException("Invalid avatar query");
    }
    if (!query.keySet().equals(Set.of("X-Goog-Algorithm", "X-Goog-Credential", "X-Goog-Date", "X-Goog-Expires", "X-Goog-SignedHeaders", "X-Goog-Signature", "generation"))
        || !"GOOG4-RSA-SHA256".equals(query.get("X-Goog-Algorithm")) || !"host".equals(query.get("X-Goog-SignedHeaders"))
        || !object.getGeneration().toString().equals(query.get("generation"))) throw new IllegalStateException("Invalid avatar scope");
    long seconds = Long.parseLong(query.get("X-Goog-Expires"));
    if (seconds < 1 || seconds > VALIDITY_SECONDS) throw new IllegalStateException("Invalid avatar lifetime");
    Instant expires = Instant.from(SIGNING_DATE.parse(query.get("X-Goog-Date"))).plusSeconds(seconds);
    requireExpiry(expires);
    return AvatarDownloadAttributes.newBuilder().setUrl(url.toASCIIString()).setExpiresAt(expires.getEpochSecond())
        .setContentLength(Math.toIntExact(object.getSize())).build();
  }

  private void requireExpiry(Instant expiry) {
    if (!expiry.isAfter(clock.instant()) || expiry.isAfter(clock.instant().plusSeconds(VALIDITY_SECONDS + 5)))
      throw new IllegalStateException("Expired or excessive avatar lifetime");
  }
  private static void requireEndpoint(URI uri, String path) {
    if (!"https".equals(uri.getScheme()) || !"storage.googleapis.com".equals(uri.getHost())
        || uri.getPort() != -1 || uri.getRawUserInfo() != null || uri.getRawFragment() != null || !path.equals(uri.getPath()))
      throw new IllegalStateException("Invalid avatar endpoint");
  }
  @Override public void close() throws Exception { storage.close(); }
}
