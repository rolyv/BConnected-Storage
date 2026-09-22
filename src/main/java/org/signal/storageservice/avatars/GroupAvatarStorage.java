// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.avatars;

import com.google.protobuf.ByteString;
import org.signal.storageservice.storage.protos.groups.AvatarDownloadAttributes;
import org.signal.storageservice.storage.protos.groups.AvatarUploadAttributes;

/** Only encrypted bytes enter object storage; the existing group encryption is unchanged. */
public interface GroupAvatarStorage {
  int MAX_CONTENT_LENGTH = 3 * 1024 * 1024;
  AvatarUploadAttributes upload(ByteString groupId);
  AvatarDownloadAttributes download(ByteString groupId, String objectId);

  static String key(ByteString groupId, String objectId) {
    if (groupId == null || groupId.size() != 32 || objectId == null
        || !objectId.matches("[A-Za-z0-9_-]{22}")) throw new IllegalArgumentException("Invalid avatar key");
    byte[] decoded = java.util.Base64.getUrlDecoder().decode(objectId);
    if (decoded.length != 16 || !java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(objectId))
      throw new IllegalArgumentException("Non-canonical avatar key");
    return "groups/" + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(groupId.toByteArray()) + "/" + objectId;
  }
}
