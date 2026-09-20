// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.storage;

import com.google.protobuf.ByteString;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import org.signal.storageservice.auth.User;
import org.signal.storageservice.storage.protos.contacts.StorageItem;
import org.signal.storageservice.storage.protos.contacts.StorageManifest;

public interface StorageStore {
  CompletableFuture<Optional<StorageManifest>> set(User user, StorageManifest manifest, List<StorageItem> inserts, List<ByteString> deletes);
  CompletableFuture<Optional<StorageManifest>> getManifest(User user);
  CompletableFuture<Optional<StorageManifest>> getManifestIfNotVersion(User user, long version);
  CompletableFuture<List<StorageItem>> getItems(User user, List<ByteString> keys);
  CompletableFuture<Void> clearItems(User user);
  CompletableFuture<Void> delete(User user);

  default CompletableFuture<Optional<StorageManifest>> write(User user, StorageManifest manifest,
      List<StorageItem> inserts, List<ByteString> deletes, boolean clearAll) {
    return (clearAll ? clearItems(user) : CompletableFuture.<Void>completedFuture(null))
        .thenCompose(ignored -> set(user, manifest, inserts, deletes));
  }
}
