// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.groups.manifests;

import com.nimbusds.jose.JWSSigner;
import org.signal.storageservice.storage.GroupAuthority;
import org.signal.storageservice.storage.protos.authority.AuthoritySnapshot;

/** Test-only bridge; production callers cannot sign arbitrary supplied authority snapshots. */
public final class ManifestTestSupport {
  private ManifestTestSupport() {}
  public static GroupManifestCodec.Envelope sign(GroupManifestCodec codec, AuthoritySnapshot state,
      String keyId, JWSSigner signer) { return codec.sign(state, keyId, signer); }
  public static GroupManifestService service(GroupAuthority authority, GroupManifestCodec codec,
      String keyId, JWSSigner signer) {
    return new GroupManifestService(authority, codec, keyId, signer, GroupManifestService.boundedExecutor());
  }
}
