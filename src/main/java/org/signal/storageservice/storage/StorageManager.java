// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.storage;

import com.google.cloud.bigtable.data.v2.BigtableDataClient;
import com.google.protobuf.ByteString;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import org.signal.storageservice.auth.User;
import org.signal.storageservice.storage.protos.contacts.StorageItem;
import org.signal.storageservice.storage.protos.contacts.StorageManifest;

public class StorageManager {
  private final StorageStore store;
  public StorageManager(BigtableDataClient client, String manifests, String items) {
    this(new BigtableStorageStore(client, manifests, items));
  }
  public StorageManager(StorageStore store) { this.store = Objects.requireNonNull(store); }
  public CompletableFuture<Optional<StorageManifest>> set(User user, StorageManifest manifest,
      List<StorageItem> inserts, List<ByteString> deletes) { return store.set(user, manifest, inserts, deletes); }
  public CompletableFuture<Optional<StorageManifest>> write(User user, StorageManifest manifest,
      List<StorageItem> inserts, List<ByteString> deletes, boolean clearAll) {
    return store.write(user, manifest, inserts, deletes, clearAll);
  }
  public CompletableFuture<Optional<StorageManifest>> getManifest(User user) { return store.getManifest(user); }
  public CompletableFuture<Optional<StorageManifest>> getManifestIfNotVersion(User user, long version) {
    return store.getManifestIfNotVersion(user, version);
  }
  public CompletableFuture<List<StorageItem>> getItems(User user, List<ByteString> keys) { return store.getItems(user, keys); }
  public CompletableFuture<Void> clearItems(User user) { return store.clearItems(user); }
  public CompletableFuture<Void> delete(User user) { return store.delete(user); }
}
