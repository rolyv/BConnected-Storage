// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.configuration;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.dropwizard.core.setup.Environment;
import io.dropwizard.lifecycle.Managed;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.signal.storageservice.storage.PostgresStorage;

public record PostgresConfiguration(@NotBlank String jdbcUrl, @NotBlank String username,
                                    String passwordEnvironmentVariable, @Min(1) @Max(30) int maximumPoolSize) {
  public PostgresConfiguration {
    if (maximumPoolSize == 0) maximumPoolSize = 5;
  }

  public PostgresStorage build(Environment environment) {
    HikariConfig config = new HikariConfig();
    config.setJdbcUrl(jdbcUrl);
    config.setUsername(username);
    if (passwordEnvironmentVariable != null) {
      String password = System.getenv(passwordEnvironmentVariable);
      if (password == null || password.isBlank()) throw new IllegalArgumentException("PostgreSQL password environment variable is missing");
      config.setPassword(password);
    }
    config.setPoolName("group-storage");
    config.setMaximumPoolSize(maximumPoolSize);
    config.setMinimumIdle(0);
    config.setConnectionTimeout(15000);
    config.setInitializationFailTimeout(15000);
    config.addDataSourceProperty("tcpKeepAlive", "true");
    config.addDataSourceProperty("socketTimeout", "30");
    config.addDataSourceProperty("options", "-c statement_timeout=15000 -c lock_timeout=5000");
    final HikariDataSource dataSource = new HikariDataSource(config);
    final ThreadPoolExecutor executor = new ThreadPoolExecutor(maximumPoolSize, maximumPoolSize, 0, TimeUnit.MILLISECONDS,
        new ArrayBlockingQueue<>(256), Thread.ofPlatform().name("group-storage-sql-", 0).factory(),
        new ThreadPoolExecutor.AbortPolicy());
    environment.lifecycle().manage(new Managed() {
      @Override public void stop() throws Exception {
        executor.shutdown();
        try { if (!executor.awaitTermination(20, TimeUnit.SECONDS)) executor.shutdownNow(); }
        finally { dataSource.close(); }
      }
    });
    return new PostgresStorage(dataSource, executor);
  }
}
