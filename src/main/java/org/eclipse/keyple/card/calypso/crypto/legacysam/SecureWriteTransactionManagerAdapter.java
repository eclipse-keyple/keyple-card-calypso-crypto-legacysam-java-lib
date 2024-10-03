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
    if (getContext().getTargetSam().getSystemKeyParameter(SystemKeyType.PERSONALIZATION) == null) {
      addTargetSamCommand(
          new CommandReadKeyParameters(getContext(), SystemKeyType.PERSONALIZATION));
    }
    addTargetSamCommand(new CommandGetChallenge(getContext(), 8));
    addTargetSamCommand(new CommandWriteSamParameters(getContext(), parameters));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager prepareTransferSystemKey(
      SystemKeyType systemKeyType, byte kvc, byte[] systemKeyParameters) {
    return prepareTransferSystemKeyInternal(systemKeyType, kvc, systemKeyParameters, false);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager prepareTransferSystemKeyDiversified(
      SystemKeyType systemKeyType, byte kvc, byte[] systemKeyParameters) {
    return prepareTransferSystemKeyInternal(systemKeyType, kvc, systemKeyParameters, true);
  }

  private SecureWriteTransactionManager prepareTransferSystemKeyInternal(
      SystemKeyType systemKeyType, byte kvc, byte[] systemKeyParameters, boolean diversified) {

    Assert.getInstance()
        .notNull(systemKeyType, "systemKeyType")
        .notNull(systemKeyParameters, "systemKeyParameters")
        .isEqual(
            systemKeyParameters.length,
            LegacySamConstants.KEY_PARAMETERS_LENGTH,
            "systemKeyParameters.length");

    if (getContext().getTargetSam().getSystemKeyParameter(SystemKeyType.PERSONALIZATION) == null) {
      addTargetSamCommand(
          new CommandReadKeyParameters(getContext(), SystemKeyType.PERSONALIZATION));
    }

    addTargetSamCommand(new CommandGetChallenge(getContext(), 8));

    addTargetSamCommand(
        new CommandWriteKey(
            getContext(),
            systemKeyType,
            LegacySamConstants.TARGET_IS_SYSTEM_KEY_FILE,
            systemKeyParameters,
            diversified));

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
    return prepareTransferWorkKeyInternal(kif, kvc, workKeyParameters, recordNumber, false);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager prepareTransferWorkKeyDiversified(
      byte kif, byte kvc, byte[] workKeyParameters, int recordNumber) {
    return prepareTransferWorkKeyInternal(kif, kvc, workKeyParameters, recordNumber, true);
  }

  private SecureWriteTransactionManager prepareTransferWorkKeyInternal(
      byte kif, byte kvc, byte[] workKeyParameters, int recordNumber, boolean diversified) {

    Assert.getInstance()
        .notNull(workKeyParameters, "workKeyParameters")
        .isEqual(
            workKeyParameters.length,
            LegacySamConstants.KEY_PARAMETERS_LENGTH,
            "workKeyParameters.length")
        .isInRange(recordNumber, 1, 126, "recordNumber");

    if (getContext().getTargetSam().getSystemKeyParameter(SystemKeyType.KEY_MANAGEMENT) == null) {
      addTargetSamCommand(new CommandReadKeyParameters(getContext(), SystemKeyType.KEY_MANAGEMENT));
    }

    addTargetSamCommand(new CommandGetChallenge(getContext(), 8));

    addTargetSamCommand(
        new CommandWriteKey(getContext(), kif, kvc, recordNumber, workKeyParameters, diversified));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager prepareTransferWorkKeyDiversified(
      byte kif, byte kvc, byte[] workKeyParameters, int recordNumber, byte[] diversifier) {

    Assert.getInstance()
        .notNull(workKeyParameters, "workKeyParameters")
        .isEqual(
            workKeyParameters.length,
            LegacySamConstants.KEY_PARAMETERS_LENGTH,
            "workKeyParameters.length")
        .isInRange(recordNumber, 1, 126, "recordNumber");

    if (getContext().getTargetSam().getSystemKeyParameter(SystemKeyType.KEY_MANAGEMENT) == null) {
      addTargetSamCommand(new CommandReadKeyParameters(getContext(), SystemKeyType.KEY_MANAGEMENT));
    }

    addTargetSamCommand(new CommandGetChallenge(getContext(), 8));

    addTargetSamCommand(
        new CommandWriteKey(getContext(), kif, kvc, recordNumber, workKeyParameters, diversifier));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager prepareTransferLock(byte lockIndex, byte lockParameters) {
    if (getContext().getTargetSam().getSystemKeyParameter(SystemKeyType.KEY_MANAGEMENT) == null) {
      addTargetSamCommand(new CommandReadKeyParameters(getContext(), SystemKeyType.KEY_MANAGEMENT));
    }
    addTargetSamCommand(new CommandGetChallenge(getContext(), 8));
    addTargetSamCommand(new CommandWriteKey(getContext(), lockIndex, lockParameters, false));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager prepareTransferLockDiversified(
      byte lockIndex, byte lockParameters) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager preparePlainWriteLock(
      byte lockIndex, byte lockParameters, byte[] lockValue) {
    Assert.getInstance()
        .notNull(lockValue, "lockValue")
        .isEqual(lockValue.length, LegacySamConstants.LOCK_VALUE_LENGTH, "lockValue.length");
    byte[] lockFile = new byte[LegacySamConstants.LOCK_FILE_SIZE];
    lockFile[0] = LegacySamConstants.LOCK_KIF;
    lockFile[1] = lockIndex;
    lockFile[7] = lockParameters;
    System.arraycopy(lockValue, 0, lockFile, 13, LegacySamConstants.LOCK_VALUE_LENGTH);
    byte[] plainDataBlock = new byte[LegacySamConstants.KEY_DATA_BLOCK_SIZE];
    System.arraycopy(lockFile, 0, plainDataBlock, 8, LegacySamConstants.LOCK_FILE_SIZE);
    plainDataBlock[38] = LegacySamConstants.TARGET_IS_LOCK_FILE;
    plainDataBlock[45] = (byte) 0x80;
    addTargetSamCommand(new CommandWriteKey(getContext(), plainDataBlock));
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

    if (getContext().getTargetSam().getSystemKeyParameter(SystemKeyType.RELOADING) == null) {
      addTargetSamCommand(new CommandReadKeyParameters(getContext(), SystemKeyType.RELOADING));
    }
    addTargetSamCommand(new CommandGetChallenge(getContext(), 8));
    addTargetSamCommand(new CommandWriteCeilings(getContext(), counterNumber, ceilingValue));

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

    if (getContext().getTargetSam().getSystemKeyParameter(SystemKeyType.RELOADING) == null) {
      addTargetSamCommand(new CommandReadKeyParameters(getContext(), SystemKeyType.RELOADING));
    }
    addTargetSamCommand(new CommandGetChallenge(getContext(), 8));
    addTargetSamCommand(
        new CommandWriteCeilings(
            getContext(), counterNumber, ceilingValue, counterIncrementAccess));

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
