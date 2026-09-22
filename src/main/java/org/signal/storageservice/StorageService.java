/*
 * Copyright 2020-2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.google.cloud.bigtable.data.v2.BigtableDataClient;
import com.google.cloud.bigtable.data.v2.BigtableDataSettings;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import io.dropwizard.auth.AuthFilter;
import io.dropwizard.auth.PolymorphicAuthDynamicFeature;
import io.dropwizard.auth.PolymorphicAuthValueFactoryProvider;
import io.dropwizard.auth.basic.BasicCredentialAuthFilter;
import io.dropwizard.auth.basic.BasicCredentials;
import io.dropwizard.core.Application;
import io.dropwizard.core.setup.Bootstrap;
import io.dropwizard.core.setup.Environment;
import java.time.Clock;
import java.util.Set;
import io.micrometer.core.instrument.Metrics;
import org.apache.commons.lang3.StringUtils;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.auth.ServerZkAuthOperations;
import org.signal.storageservice.auth.ExternalGroupCredentialGenerator;
import org.signal.storageservice.auth.ExternalServiceCredentialValidator;
import org.signal.storageservice.auth.GroupUser;
import org.signal.storageservice.auth.GroupUserAuthenticator;
import org.signal.storageservice.auth.User;
import org.signal.storageservice.auth.UserAuthenticator;
import org.signal.storageservice.configuration.SecretManagerConfigurationSourceProvider;
import org.signal.storageservice.controllers.GroupsController;
import org.signal.storageservice.controllers.GroupsV1Controller;
import org.signal.storageservice.controllers.HealthCheckController;
import org.signal.storageservice.controllers.ReadinessController;
import org.signal.storageservice.controllers.PostgresReadinessController;
import org.signal.storageservice.storage.PostgresStorage;
import org.signal.storageservice.controllers.StorageController;
import org.signal.storageservice.filters.TimestampResponseFilter;
import org.signal.storageservice.metrics.MetricsHttpEventHandler;
import org.signal.storageservice.metrics.MetricsUtil;
import org.signal.storageservice.providers.CompletionExceptionMapper;
import org.signal.storageservice.providers.InvalidProtocolBufferExceptionMapper;
import org.signal.storageservice.providers.ProtocolBufferMessageBodyProvider;
import org.signal.storageservice.providers.ProtocolBufferValidationErrorMessageBodyWriter;
import org.signal.storageservice.storage.GroupsManager;
import org.signal.storageservice.storage.StorageManager;
import org.signal.storageservice.util.UncaughtExceptionHandler;
import org.signal.storageservice.util.logging.LoggingUnhandledExceptionMapper;

public class StorageService extends Application<StorageServiceConfiguration> {

  /// The name of an environment variable that may contain a Secret Manager URI that points to a secret that contains a
  /// complete [StorageServiceConfiguration] entity serialized as YAML. If specified, then the storage service will read
  /// its configuration from the named secret and will ignore (but still require) the configuration file argument.
  private static final String CONFIG_URI_ENVIRONMENT_VARIABLE = "STORAGE_SERVICE_CONFIG_URI";

  @Override
  public void initialize(final Bootstrap<StorageServiceConfiguration> bootstrap) {
    final String configurationUri = System.getenv(CONFIG_URI_ENVIRONMENT_VARIABLE);

    if (StringUtils.isNotBlank(configurationUri)) {
      bootstrap.setConfigurationSourceProvider(new SecretManagerConfigurationSourceProvider(configurationUri));
    }
  }

  @Override
  public void run(StorageServiceConfiguration config, Environment environment) throws Exception {
    MetricsUtil.configureRegistries(config, environment);
    MetricsUtil.configureLogging(config, environment);

    UncaughtExceptionHandler.register();

    if (!config.isPersistenceConfigurationValid()) {
      throw new IllegalArgumentException("Select PostgreSQL without Bigtable/CDN, or configure the legacy Bigtable/CDN backend");
    }
    final StorageManager storageManager;
    final GroupsManager groupsManager;
    final Object readiness;
    if (config.getPostgresConfiguration() != null) {
      final PostgresStorage postgres = config.getPostgresConfiguration().build(environment);
      postgres.checkReady();
      storageManager = new StorageManager(postgres);
      groupsManager = new GroupsManager(postgres);
      readiness = new PostgresReadinessController(postgres);
    } else {
      final BigtableDataSettings settings = BigtableDataSettings.newBuilder()
          .setProjectId(config.getBigTableConfiguration().getProjectId())
          .setInstanceId(config.getBigTableConfiguration().getInstanceId()).build();
      final BigtableDataClient client = BigtableDataClient.create(settings);
      environment.lifecycle().manage(new io.dropwizard.lifecycle.Managed() {
        @Override public void stop() { client.close(); }
      });
      storageManager = new StorageManager(client, config.getBigTableConfiguration().getContactManifestsTableId(),
          config.getBigTableConfiguration().getContactsTableId());
      groupsManager = new GroupsManager(client, config.getBigTableConfiguration().getGroupsTableId(),
          config.getBigTableConfiguration().getGroupLogsTableId());
      readiness = new ReadinessController(client,
          Set.of(config.getBigTableConfiguration().getGroupsTableId(), config.getBigTableConfiguration().getGroupLogsTableId(),
              config.getBigTableConfiguration().getContactsTableId(), config.getBigTableConfiguration().getContactManifestsTableId()),
          config.getWarmUpConfiguration().count());
    }
    final ServerSecretParams serverSecretParams = new ServerSecretParams(config.getZkConfiguration().getServerSecret());

    environment.getObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    environment.getObjectMapper().setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.NONE);
    environment.getObjectMapper().setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);

    environment.jersey().register(ProtocolBufferMessageBodyProvider.class);
    environment.jersey().register(ProtocolBufferValidationErrorMessageBodyWriter.class);
    environment.jersey().register(InvalidProtocolBufferExceptionMapper.class);
    environment.jersey().register(CompletionExceptionMapper.class);
    environment.jersey().register(new LoggingUnhandledExceptionMapper());

    UserAuthenticator      userAuthenticator      = new UserAuthenticator(new ExternalServiceCredentialValidator(config.getAuthenticationConfiguration().getKey()));
    GroupUserAuthenticator groupUserAuthenticator = new GroupUserAuthenticator(new ServerZkAuthOperations(serverSecretParams));
    ExternalGroupCredentialGenerator externalGroupCredentialGenerator = new ExternalGroupCredentialGenerator(
        config.getGroupConfiguration().externalServiceSecret(), Clock.systemUTC());

    AuthFilter<BasicCredentials, User>      userAuthFilter      = new BasicCredentialAuthFilter.Builder<User>().setAuthenticator(userAuthenticator).buildAuthFilter();
    AuthFilter<BasicCredentials, GroupUser> groupUserAuthFilter = new BasicCredentialAuthFilter.Builder<GroupUser>().setAuthenticator(groupUserAuthenticator).buildAuthFilter();


    environment.jersey().register(new PolymorphicAuthDynamicFeature<>(ImmutableMap.of(User.class, userAuthFilter, GroupUser.class, groupUserAuthFilter)));
    environment.jersey().register(new PolymorphicAuthValueFactoryProvider.Binder<>(ImmutableSet.of(User.class, GroupUser.class)));

    environment.jersey().register(new TimestampResponseFilter(Clock.systemUTC()));

    environment.jersey().register(new HealthCheckController());
    environment.jersey().register(readiness);
    environment.jersey().register(new StorageController(storageManager));
    org.signal.storageservice.avatars.GroupAvatarService avatars = null;
    if (config.getGroupAvatars() != null) {
      var objects = config.getGroupAvatars().build(Clock.systemUTC());
      environment.lifecycle().manage(new io.dropwizard.lifecycle.Managed() {
        @Override public void stop() throws Exception { objects.close(); }
      });
      var workers = environment.lifecycle().executorService("group-avatar-%d").minThreads(4).maxThreads(4)
          .workQueue(new java.util.concurrent.ArrayBlockingQueue<>(16)).build();
      avatars = new org.signal.storageservice.avatars.GroupAvatarService(objects, groupsManager, workers, Clock.systemUTC());
    }
    environment.jersey().register(new GroupsController(Clock.systemUTC(), groupsManager, serverSecretParams, config.getGroupConfiguration(), externalGroupCredentialGenerator, avatars));
    environment.jersey().register(new GroupsV1Controller(Clock.systemUTC(), groupsManager, serverSecretParams, config.getGroupConfiguration(), externalGroupCredentialGenerator, avatars));

    MetricsHttpEventHandler.configure(environment, Metrics.globalRegistry, Set.of("/health-check"));

    MetricsUtil.registerSystemResourceMetrics(environment);
  }

  public static void main(String[] argv) throws Exception {
    new StorageService().run(argv);
  }
}
