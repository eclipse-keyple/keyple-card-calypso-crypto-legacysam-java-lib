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

import static org.eclipse.keyple.card.calypso.crypto.legacysam.DtoAdapters.*;

import com.google.gson.JsonObject;
import java.util.*;
import org.calypsonet.terminal.calypso.crypto.legacysam.transaction.*;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.json.JsonUtil;

/**
 * Adapter of {@link LSAsyncTransactionCreatorManager}.
 *
 * @since 0.3.0
 */
class LSAsyncTransactionCreatorManagerAdapter extends CommonTransactionManagerAdapter
    implements LSAsyncTransactionCreatorManager {

  /* Final fields */
  private final TargetSamContextDto targetSamContext;

  /**
   * Constructs a new instance with the specified target SAM context and security settings.
   *
   * @param targetSamContextJSon The target SAM context as a JSon String.
   * @param lsSecuritySetting An instance of {@link LSSecuritySetting}.
   * @since 0.3.0
   */
  LSAsyncTransactionCreatorManagerAdapter(
      String targetSamContextJSon, LSSecuritySetting lsSecuritySetting) {
    super(
        null,
        null,
        ((LSSecuritySettingAdapter) lsSecuritySetting).getControlSamReader(),
        ((LSSecuritySettingAdapter) lsSecuritySetting).getControlSam());
    this.targetSamContext =
        JsonUtil.getParser().fromJson(targetSamContextJSon, TargetSamContextDto.class);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  public LSAsyncTransactionCreatorManager prepareWriteCounterCeiling(
      int counterNumber, int ceilingValue) {

    Assert.getInstance()
        .isInRange(
            counterNumber, MIN_COUNTER_CEILING_NUMBER, MAX_COUNTER_CEILING_NUMBER, "counterNumber")
        .isInRange(
            ceilingValue, MIN_COUNTER_CEILING_VALUE, MAX_COUNTER_CEILING_VALUE, "ceilingValue");

    addTargetSamCommand(
        new CommandWriteCeilings(getContext(), targetSamContext, counterNumber, ceilingValue));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  public LSAsyncTransactionCreatorManager prepareWriteCounterConfiguration(
      int counterNumber, int ceilingValue, boolean isManualCounterIncrementAuthorized) {

    Assert.getInstance()
        .isInRange(
            counterNumber, MIN_COUNTER_CEILING_NUMBER, MAX_COUNTER_CEILING_NUMBER, "counterNumber")
        .isInRange(
            ceilingValue, MIN_COUNTER_CEILING_VALUE, MAX_COUNTER_CEILING_VALUE, "ceilingValue");

    for (Command command : getTargetSamCommands()) {
      if (command instanceof CommandWriteCeilings
          && ((CommandWriteCeilings) command).getCounterFileRecordNumber()
              == counterToRecordLookup[counterNumber]) {
        ((CommandWriteCeilings) command)
            .addCounter(counterNumber, ceilingValue, isManualCounterIncrementAuthorized);
        return this;
      }
    }

    addTargetSamCommand(
        new CommandWriteCeilings(
            getContext(),
            targetSamContext,
            counterNumber,
            ceilingValue,
            isManualCounterIncrementAuthorized));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  public String exportCommands() {
    List<Command> commands = getTargetSamCommands();
    for (Command command : commands) {
      command.finalizeRequest();
    }
    JsonObject jsonObject = new JsonObject();

    List<String> cardCommandTypes = new ArrayList<String>(commands.size());
    for (Command command : commands) {
      cardCommandTypes.add(command.getClass().getName());
    }
    jsonObject.add(SAM_COMMANDS_TYPES, JsonUtil.getParser().toJsonTree(cardCommandTypes));
    jsonObject.add(SAM_COMMANDS, JsonUtil.getParser().toJsonTree(commands));

    return jsonObject.toString();
  }

  /**
   * {@inheritDoc}
   *
   * <p>This method is part of the implemented interface, but it cannot be executed by this type of
   * transaction manager, which is not designed to handle target SAM commands. As a result, when
   * called, this method always throws an exception.
   *
   * @throws IllegalStateException Always.
   * @since 0.3.0
   */
  @Override
  public LSAsyncTransactionCreatorManager processCommands() {
    throw new IllegalStateException(
        "processCommands() is not allowed during the creation of an asynchronous transaction.");
  }
}
