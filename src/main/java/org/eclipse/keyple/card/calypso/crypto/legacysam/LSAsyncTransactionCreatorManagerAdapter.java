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

public class LSAsyncTransactionCreatorManagerAdapter extends CommonTransactionManagerAdapter
    implements LSAsyncTransactionCreatorManager {

  /* Final fields */
  private final TargetSamContextDto targetSamContext;

  LSAsyncTransactionCreatorManagerAdapter(
      String targetSamContext, LSSecuritySetting lsSecuritySetting) {
    super(
        null,
        null,
        ((LSSecuritySettingAdapter) lsSecuritySetting).getControlSamReader(),
        ((LSSecuritySettingAdapter) lsSecuritySetting).getControlSam());
    this.targetSamContext =
        JsonUtil.getParser().fromJson(targetSamContext, TargetSamContextDto.class);
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

  @Override
  public LSAsyncTransactionCreatorManager processCommands() {
    throw new IllegalStateException(
        "processCommands() is not allowed during the creation of an asynchronous transaction. Use exportCommands().");
  }
}
