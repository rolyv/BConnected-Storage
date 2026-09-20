// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.signal.libsignal.zkgroup.ServerSecretParams;

/** Mount a narrow Secret Manager bundle; no secrets are passed in arguments, committed, or printed. */
public final class BConnectedStorageLauncher {
  private BConnectedStorageLauncher() {}

  static Map<String, Object> configuration(Map<String, String> secrets, Map<String, String> environment) throws Exception {
    byte[] groupSecret = decode(secrets, "groups.serverSecret", -1);
    // Reject malformed cryptographic parameters before writing a configuration file.
    new ServerSecretParams(groupSecret);
    String authentication = HexFormat.of().formatHex(decode(secrets, "storage.authentication", 32));
    String external = HexFormat.of().formatHex(decode(secrets, "groups.externalService", 32));
    String jdbc = environment.getOrDefault("GROUP_STORAGE_JDBC_URL", "jdbc:postgresql://127.0.0.1:5432/bconnected?sslmode=disable");
    String username = environment.getOrDefault("GROUP_STORAGE_DB_USER", "bconnected-groups@roly-dev.iam");
    int port = Integer.parseInt(environment.getOrDefault("PORT", "8080"));
    int adminPort = Integer.parseInt(environment.getOrDefault("GROUP_STORAGE_ADMIN_PORT", "8081"));
    if (port < 1 || port > 65535 || adminPort < 1 || adminPort > 65535 || port == adminPort) {
      throw new IllegalArgumentException("Distinct valid application and admin ports are required");
    }
    var postgres = new java.util.LinkedHashMap<String, Object>();
    postgres.put("jdbcUrl", jdbc);
    postgres.put("username", username);
    postgres.put("maximumPoolSize", 5);
    if (environment.containsKey("GROUP_STORAGE_PASSWORD_ENV")) {
      postgres.put("passwordEnvironmentVariable", environment.get("GROUP_STORAGE_PASSWORD_ENV"));
    }
    return Map.of(
        "postgres", postgres,
        "authentication", Map.of("key", authentication),
        "zkConfig", Map.of("serverSecret", Base64.getEncoder().encodeToString(groupSecret)),
        "group", Map.of("maxGroupSize", 10000, "maxGroupTitleLengthBytes", 1024,
            "maxGroupDescriptionLengthBytes", 8192, "externalServiceSecret", external),
        "openTelemetry", Map.of("enabled", false, "environment", "bconnected-pilot"),
        "server", Map.of("applicationConnectors", List.of(Map.of("type", "http", "port", port,
                "bindHost", environment.getOrDefault("GROUP_STORAGE_BIND_HOST", "127.0.0.1"))),
            "adminConnectors", List.of(Map.of("type", "http", "port", adminPort, "bindHost", "127.0.0.1")),
            "requestLog", Map.of("appenders", List.of())),
        "logging", Map.of("level", "INFO", "appenders", List.of(Map.of("type", "console"))));
  }

  private static byte[] decode(Map<String, String> secrets, String key, int size) {
    final byte[] value;
    try { value = Base64.getDecoder().decode(java.util.Objects.requireNonNull(secrets.get(key))); }
    catch (RuntimeException ignored) { throw new IllegalArgumentException("Required runtime secret is missing or malformed"); }
    if (size > 0 && value.length != size) throw new IllegalArgumentException("Runtime secret has an invalid length");
    return value;
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 0) throw new IllegalArgumentException("This launcher accepts configuration only through mounted secrets and environment");
    if (System.getenv("STORAGE_SERVICE_CONFIG_URI") != null) {
      throw new IllegalArgumentException("Do not combine the pilot bundle launcher with the legacy full-configuration secret override");
    }
    String bundlePath = System.getenv("GROUP_STORAGE_SECRETS_FILE");
    if (bundlePath == null || bundlePath.isBlank()) throw new IllegalArgumentException("GROUP_STORAGE_SECRETS_FILE is required");
    var mapper = new ObjectMapper();
    final Map<String, Object> config;
    try (var input = Files.newInputStream(Path.of(bundlePath))) {
      config = configuration(mapper.readValue(input, new TypeReference<Map<String, String>>() {}), System.getenv());
    } catch (Exception ignored) {
      // Jackson diagnostics can include source fragments; never emit the mounted secret document.
      throw new IllegalArgumentException("Unable to load the storage-service runtime bundle or configuration");
    }
    Path file = Files.createTempFile("bconnected-storage-", ".json", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
    file.toFile().deleteOnExit();
    Files.write(file, mapper.writeValueAsBytes(config));
    new StorageService().run("server", file.toString());
  }
}
