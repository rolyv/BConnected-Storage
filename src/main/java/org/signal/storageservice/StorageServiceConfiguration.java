/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.vdurmont.semver4j.Semver;
import io.dropwizard.core.Configuration;
import org.signal.storageservice.configuration.AuthenticationConfiguration;
import org.signal.storageservice.configuration.BigTableConfiguration;
import org.signal.storageservice.configuration.OpenTelemetryConfiguration;
import org.signal.storageservice.configuration.GroupConfiguration;
import org.signal.storageservice.configuration.WarmupConfiguration;
import org.signal.storageservice.configuration.ZkConfiguration;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.AssertTrue;
import com.fasterxml.jackson.annotation.JsonIgnore;
import org.signal.storageservice.configuration.PostgresConfiguration;
import org.signal.storageservice.util.ua.ClientPlatform;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

public class StorageServiceConfiguration extends Configuration {

  @JsonProperty
  @Valid
  private org.signal.storageservice.configuration.GcsGroupAvatarConfiguration groupAvatars;

  public org.signal.storageservice.configuration.GcsGroupAvatarConfiguration getGroupAvatars() { return groupAvatars; }

  @JsonProperty
  @Valid
  private BigTableConfiguration bigtable;

  @JsonProperty
  @Valid
  private PostgresConfiguration postgres;

  public PostgresConfiguration getPostgresConfiguration() { return postgres; }

  @JsonIgnore
  @AssertTrue(message = "Select exactly one of PostgreSQL or Bigtable")
  public boolean isPersistenceConfigurationValid() {
    return (postgres != null) != (bigtable != null);
  }

  @JsonProperty
  @Valid
  @NotNull
  private AuthenticationConfiguration authentication;

  @JsonProperty
  @Valid
  @NotNull
  private ZkConfiguration zkConfig;

  @JsonProperty("cdn")
  public void rejectLegacyCdn(Object ignored) {
    throw new IllegalArgumentException("Legacy CDN configuration is no longer supported");
  }

  @JsonProperty
  @Valid
  @NotNull
  private GroupConfiguration group;

  @JsonProperty
  @Valid
  @NotNull
  private OpenTelemetryConfiguration openTelemetry;

  @JsonProperty
  @Valid
  @NotNull
  private WarmupConfiguration warmup = new WarmupConfiguration(5);

  @JsonProperty
  @NotNull
  private Map<ClientPlatform, Set<Semver>> recognizedClientVersions = Collections.emptyMap();

  public BigTableConfiguration getBigTableConfiguration() {
    return bigtable;
  }

  public AuthenticationConfiguration getAuthenticationConfiguration() {
    return authentication;
  }

  public ZkConfiguration getZkConfiguration() {
    return zkConfig;
  }

  public GroupConfiguration getGroupConfiguration() {
    return group;
  }

  public OpenTelemetryConfiguration getOpenTelemetryConfiguration() {
    return openTelemetry;
  }

  public WarmupConfiguration getWarmUpConfiguration() {
    return warmup;
  }

  public Map<ClientPlatform, Set<Semver>> getRecognizedClientVersions() {
    return recognizedClientVersions;
  }
}
