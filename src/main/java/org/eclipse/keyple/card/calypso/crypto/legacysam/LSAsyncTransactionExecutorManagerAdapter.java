/* **************************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information
 * regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ************************************************************************************** */
package org.eclipse.keyple.card.calypso.crypto.legacysam;

import static org.eclipse.keyple.card.calypso.crypto.legacysam.CommonTransactionManagerAdapter.SAM_COMMANDS;
import static org.eclipse.keyple.card.calypso.crypto.legacysam.CommonTransactionManagerAdapter.SAM_COMMANDS_TYPES;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import java.util.ArrayList;
import java.util.List;
import org.calypsonet.terminal.calypso.crypto.legacysam.transaction.LSAsyncTransactionExecutorManager;
import org.calypsonet.terminal.card.ProxyReaderApi;
import org.eclipse.keyple.core.util.json.JsonUtil;

public class LSAsyncTransactionExecutorManagerAdapter extends CommonTransactionManagerAdapter
    implements LSAsyncTransactionExecutorManager {

  LSAsyncTransactionExecutorManagerAdapter(
      ProxyReaderApi samReader, LegacySamAdapter sam, String samCommands) {
    super(samReader, sam, null, null);

    JsonObject jsonObject = JsonUtil.getParser().fromJson(samCommands, JsonObject.class);

    // extract the type and command lists
    List<String> commandsTypes =
        JsonUtil.getParser()
            .fromJson(
                jsonObject.get(SAM_COMMANDS_TYPES).getAsJsonArray(),
                new TypeToken<ArrayList<String>>() {}.getType());
    JsonArray commands = jsonObject.get(SAM_COMMANDS).getAsJsonArray();

    for (int i = 0; i < commandsTypes.size(); i++) {
      // check the resulting command class
      try {
        Class<?> classOfCommand = Class.forName(commandsTypes.get(i));
        addTargetSamCommand(
            (Command) JsonUtil.getParser().fromJson(commands.get(i), classOfCommand));
      } catch (ClassNotFoundException e) {
        throw new IllegalStateException("Invalid JSON commands object.");
      }
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  public LSAsyncTransactionExecutorManager processCommands() {
    processTargetSamCommands(false);
    return this;
  }
}
