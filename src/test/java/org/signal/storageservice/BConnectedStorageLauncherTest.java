// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.dropwizard.jackson.Jackson;
import jakarta.validation.Validation;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.signal.libsignal.zkgroup.ServerSecretParams;

class BConnectedStorageLauncherTest {
  private static Map<String, String> secrets() {
    return Map.of("groups.serverSecret", Base64.getEncoder().encodeToString(ServerSecretParams.generate().serialize()),
        "storage.authentication", Base64.getEncoder().encodeToString(new byte[32]),
        "groups.externalService", Base64.getEncoder().encodeToString(new byte[32]));
  }

  @Test void pilotConfigurationValidatesWithoutBigtableOrAwsAndRetainsTenThousandLimit() throws Exception {
    var objectMapper = Jackson.newObjectMapper();
    var configuration = objectMapper.convertValue(BConnectedStorageLauncher.configuration(secrets(), Map.of()), StorageServiceConfiguration.class);
    try (var factory = Validation.buildDefaultValidatorFactory()) {
      assertThat(factory.getValidator().validate(configuration)).isEmpty();
    }
    assertThat(configuration.getBigTableConfiguration()).isNull();
    assertThat(configuration.getCdnConfiguration()).isNull();
    assertThat(configuration.getGroupConfiguration().maxGroupSize()).isEqualTo(10000);
    assertThat(configuration.getAuthenticationConfiguration().getKey()).hasSize(32);
  }

  @Test void rejectsMissingOrMalformedSecretsWithoutIncludingValuesInErrors() {
    assertThatThrownBy(() -> BConnectedStorageLauncher.configuration(Map.of("groups.serverSecret", "do-not-log-this"), Map.of()))
        .isInstanceOf(IllegalArgumentException.class).hasMessageNotContaining("do-not-log-this");
  }

  @Test void requiresDistinctApplicationAndAdminPorts() {
    assertThatThrownBy(() -> BConnectedStorageLauncher.configuration(secrets(), Map.of("PORT", "8081")))
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Distinct valid");
  }

  @Test void rejectsMixedPersistenceConfigurationAndS3CdnInPostgresMode() throws Exception {
    var mapper = Jackson.newObjectMapper();
    var mixed = new java.util.LinkedHashMap<>(BConnectedStorageLauncher.configuration(secrets(), Map.of()));
    mixed.put("bigtable", Map.of());
    assertThat(mapper.convertValue(mixed, StorageServiceConfiguration.class).isPersistenceConfigurationValid()).isFalse();
    mixed.remove("bigtable");
    mixed.put("cdn", Map.of());
    assertThat(mapper.convertValue(mixed, StorageServiceConfiguration.class).isPersistenceConfigurationValid()).isFalse();
    mixed.remove("cdn");
    mixed.remove("postgres");
    assertThat(mapper.convertValue(mixed, StorageServiceConfiguration.class).isPersistenceConfigurationValid()).isFalse();
  }
}
