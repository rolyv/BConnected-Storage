// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.controllers;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.postgresql.ds.PGSimpleDataSource;
import org.signal.storageservice.storage.GroupsManager;
import org.signal.storageservice.storage.PostgresStorage;

/** Creates/drops only its own randomly named database on an explicitly selected loopback fixture. */
final class DisposableGroupDatabase implements AutoCloseable {
  private final PGSimpleDataSource operator;
  private final String name;
  private final String jdbcUrl;
  final PGSimpleDataSource dataSource;
  private ExecutorService executor;
  final PostgresStorage storage;
  final GroupsManager manager;
  private boolean created;

  DisposableGroupDatabase() throws Exception {
    String configuredUrl = System.getenv("BCONNECTED_GROUP_TEST_JDBC_URL");
    if (configuredUrl == null || !configuredUrl.startsWith("jdbc:postgresql://")) {
      throw new IllegalArgumentException("Capacity tests require an explicit loopback test database");
    }
    URI uri = URI.create(configuredUrl.substring("jdbc:".length()));
    if (!List.of("127.0.0.1", "localhost", "::1").contains(uri.getHost())
        || !uri.getPath().matches("/[a-zA-Z0-9_]+_test")
        || uri.getQuery() != null || uri.getUserInfo() != null || uri.getFragment() != null) {
      throw new IllegalArgumentException("Only a plain loopback database ending in _test is permitted");
    }
    operator = localDataSource(uri, uri.getPath().substring(1));
    name = "bconnected_capacity_" + UUID.randomUUID().toString().replace("-", "") + "_test";
    dataSource = localDataSource(uri, name);
    jdbcUrl = "jdbc:postgresql://" + uri.getRawAuthority() + "/" + name;
    try {
      try (var connection = operator.getConnection(); var statement = connection.createStatement()) {
        statement.execute("CREATE DATABASE " + name);
        created = true;
      }
      try (var connection = dataSource.getConnection(); var statement = connection.createStatement()) {
        statement.execute(Files.readString(Path.of("bconnected/migrations/001-postgres.sql")));
      statement.execute(Files.readString(Path.of("bconnected/migrations/002-group-authority.sql")));
      }
      executor = Executors.newFixedThreadPool(2);
      storage = new PostgresStorage(dataSource, executor);
      manager = new GroupsManager(storage);
    } catch (Exception failure) {
      close();
      throw failure;
    }
  }

  String jdbcUrl() { return jdbcUrl; }

  private static PGSimpleDataSource localDataSource(URI uri, String name) {
    var result = new PGSimpleDataSource();
    result.setServerNames(new String[] {uri.getHost()});
    result.setPortNumbers(new int[] {uri.getPort() < 0 ? 5432 : uri.getPort()});
    result.setDatabaseName(name);
    result.setUser("postgres");
    result.setPassword(System.getenv("BCONNECTED_TEST_POSTGRES_PASSWORD"));
    result.setConnectTimeout(5);
    result.setSocketTimeout(30);
    result.setOptions("-c statement_timeout=15000 -c lock_timeout=5000");
    return result;
  }

  @Override public void close() throws Exception {
    try {
      if (executor != null) executor.close();
    } finally {
      if (created) {
        try (var connection = operator.getConnection(); var statement = connection.createStatement()) {
          statement.execute("DROP DATABASE " + name + " WITH (FORCE)");
          created = false;
        }
      }
    }
  }

  @Override public String toString() { return "DisposableGroupDatabase[redacted]"; }
}
