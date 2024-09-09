/* **************************************************************************************
 * Copyright (c) 2024 Calypso Networks Association https://calypsonet.org/
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

import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keypop.calypso.crypto.legacysam.CounterIncrementAccess;
import org.eclipse.keypop.calypso.crypto.legacysam.SystemKeyType;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.SecureWriteTransactionManager;
import org.eclipse.keypop.card.ProxyReaderApi;

/**
 * Adapter of {@link SecureWriteTransactionManager}.
 *
 * @since 0.9.0
 */
public class SecureWriteTransactionManagerAdapter extends CommonTransactionManagerAdapter
    implements SecureWriteTransactionManager {

  private final DtoAdapters.TargetSamContextDto targetSamContext;

  /**
   * Constructor
   *
   * @param targetSamReader The reader through which the target SAM communicates.
   * @param targetSam The target legacy SAM.
   * @param controlSamReader The reader through which the control SAM communicates.
   * @param controlSam The control legacy SAM.
   */
  SecureWriteTransactionManagerAdapter(
      ProxyReaderApi targetSamReader,
      LegacySamAdapter targetSam,
      ProxyReaderApi controlSamReader,
      LegacySamAdapter controlSam) {
    super(targetSamReader, targetSam, controlSamReader, controlSam);
    targetSamContext =
        new DtoAdapters.TargetSamContextDto(getContext().getTargetSam().getSerialNumber(), false);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager prepareWriteSamParameters(byte[] parameters) {
    Assert.getInstance()
        .notNull(parameters, "parameters")
        .isEqual(parameters.length, LegacySamConstants.SAM_PARAMETERS_LENGTH, "parameters.length");
    if (targetSamContext.isDynamicMode()) {
      addTargetSamCommand(new CommandGetChallenge(getContext(), 8));
    }
    addTargetSamCommand(new CommandWriteSamParameters(getContext(), targetSamContext, parameters));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager prepareTransferSystemKey(
      SystemKeyType systemKeyType, byte[] systemKeyParameters) {
    Assert.getInstance()
        .notNull(systemKeyType, "systemKeyType")
        .notNull(systemKeyParameters, "systemKeyParameters")
        .isEqual(
            systemKeyParameters.length,
            LegacySamConstants.KEY_PARAMETERS_LENGTH,
            "systemKeyParameters.length");
    if (targetSamContext.isDynamicMode()) {
      addTargetSamCommand(new CommandGetChallenge(getContext(), 8));
    }
    addTargetSamCommand(
        new CommandWriteKey(getContext(), targetSamContext, (byte) 0xC0, systemKeyParameters));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager prepareTransferWorkKey(
      byte kif, byte kvc, byte[] workKeyParameters, int recordNumber) {
    Assert.getInstance()
        .notNull(workKeyParameters, "workKeyParameters")
        .isEqual(
            workKeyParameters.length,
            LegacySamConstants.KEY_PARAMETERS_LENGTH,
            "workKeyParameters.length")
        .isInRange(recordNumber, 1, 126, "recordNumber");
    if (targetSamContext.isDynamicMode()) {
      addTargetSamCommand(new CommandGetChallenge(getContext(), 8));
    }
    addTargetSamCommand(
        new CommandWriteKey(
            getContext(), targetSamContext, (byte) recordNumber, workKeyParameters));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager prepareWriteCounterCeiling(
      int counterNumber, int ceilingValue) {

    Assert.getInstance()
        .isInRange(
            counterNumber,
            LegacySamConstants.MIN_COUNTER_CEILING_NUMBER,
            LegacySamConstants.MAX_COUNTER_CEILING_NUMBER,
            "counterNumber")
        .isInRange(
            ceilingValue,
            LegacySamConstants.MIN_COUNTER_CEILING_VALUE,
            LegacySamConstants.MAX_COUNTER_CEILING_VALUE,
            "ceilingValue");

    if (targetSamContext.isDynamicMode()) {
      addTargetSamCommand(new CommandGetChallenge(getContext(), 8));
    }
    addTargetSamCommand(
        new CommandWriteCeilings(getContext(), targetSamContext, counterNumber, ceilingValue));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager prepareWriteCounterConfiguration(
      int counterNumber, int ceilingValue, CounterIncrementAccess counterIncrementAccess) {

    Assert.getInstance()
        .isInRange(
            counterNumber,
            LegacySamConstants.MIN_COUNTER_CEILING_NUMBER,
            LegacySamConstants.MAX_COUNTER_CEILING_NUMBER,
            "counterNumber")
        .isInRange(
            ceilingValue,
            LegacySamConstants.MIN_COUNTER_CEILING_VALUE,
            LegacySamConstants.MAX_COUNTER_CEILING_VALUE,
            "ceilingValue");

    for (Command command : getTargetSamCommands()) {
      if (command instanceof CommandWriteCeilings
          && ((CommandWriteCeilings) command).getCounterFileRecordNumber()
              == LegacySamConstants.COUNTER_TO_RECORD_LOOKUP[counterNumber]) {
        ((CommandWriteCeilings) command)
            .addCounter(counterNumber, ceilingValue, counterIncrementAccess);
        return this;
      }
    }

    if (targetSamContext.isDynamicMode()) {
      addTargetSamCommand(new CommandGetChallenge(getContext(), 8));
    }
    addTargetSamCommand(
        new CommandWriteCeilings(
            getContext(), targetSamContext, counterNumber, ceilingValue, counterIncrementAccess));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager processCommands() {
    processTargetSamCommands(false);
    return this;
  }
}
