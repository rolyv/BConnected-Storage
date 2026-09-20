// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.storageservice.controllers;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.ServiceUnavailableException;
import java.sql.SQLException;
import org.signal.storageservice.storage.PostgresStorage;

@Path("_ready")
public final class PostgresReadinessController {
  private final PostgresStorage store;
  public PostgresReadinessController(PostgresStorage store) { this.store = store; }
  @GET public String isReady() {
    try { store.checkReady(); return "ready"; }
    catch (SQLException e) { throw new ServiceUnavailableException("Storage database is unavailable"); }
  }
}
