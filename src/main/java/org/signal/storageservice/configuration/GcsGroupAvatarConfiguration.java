// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.configuration;

import com.google.auth.ServiceAccountSigner;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ImpersonatedCredentials;
import com.google.cloud.storage.StorageOptions;
import java.io.IOException;
import java.time.Clock;
import java.util.List;
import org.signal.storageservice.avatars.GcsGroupAvatarStorage;

/** Attached ADC and IAM signBlob; no exported service-account private key or public bucket. */
public record GcsGroupAvatarConfiguration(String bucket, String signingServiceAccount) {
  public GcsGroupAvatarConfiguration {
    if (bucket == null || !bucket.matches("[a-z0-9][a-z0-9_-]{1,61}[a-z0-9]"))
      throw new IllegalArgumentException("A dedicated GCS bucket is required");
    if (signingServiceAccount == null || !signingServiceAccount.matches("[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\\.gserviceaccount\\.com"))
      throw new IllegalArgumentException("An IAM signing service account is required");
  }
  public GcsGroupAvatarStorage build(Clock clock) throws IOException {
    var scopes = List.of("https://www.googleapis.com/auth/cloud-platform");
    var credentials = GoogleCredentials.getApplicationDefault().createScoped(scopes);
    var impersonated = ImpersonatedCredentials.create(credentials, signingServiceAccount, List.of(), scopes, 3600);
    ServiceAccountSigner signer = new ServiceAccountSigner() {
      @Override public String getAccount() { return impersonated.getAccount(); }
      @Override public byte[] sign(byte[] bytes) { return impersonated.sign(bytes); }
    };
    var transport = StorageOptions.getDefaultHttpTransportOptions().toBuilder().setConnectTimeout(5000).setReadTimeout(10000).build();
    var retries = StorageOptions.getDefaultRetrySettings().toBuilder().setMaxAttempts(2)
        .setTotalTimeoutDuration(java.time.Duration.ofSeconds(15)).build();
    var storage = StorageOptions.newBuilder().setCredentials(credentials).setTransportOptions(transport).setRetrySettings(retries).build().getService();
    return new GcsGroupAvatarStorage(storage, bucket, signer, clock);
  }
}
