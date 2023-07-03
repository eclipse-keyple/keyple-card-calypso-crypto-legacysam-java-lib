/* **************************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://calypsonet.org/
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
import static org.eclipse.keyple.card.calypso.crypto.legacysam.DtoAdapters.CommandContextDto;

import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keypop.calypso.crypto.legacysam.CounterIncrementAccess;
import org.eclipse.keypop.calypso.crypto.legacysam.SystemKeyType;
import org.eclipse.keypop.card.ApduResponseApi;

/**
 * Builds the Write Ceilings APDU command.
 *
 * @since 0.1.0
 */
final class CommandWriteCeilings extends Command {
  private final transient TargetSamContextDto targetSamContext; // NOSONAR
  private final transient byte[] plainData = new byte[30]; // NOSONAR
  private final transient Map<Integer, CounterIncrementAccess>
      counterNumberToManualCounterIncrementAuthorizedMap =
          new HashMap<Integer, CounterIncrementAccess>(); // NOSONAR
  private final transient int counterFileRecordNumber; // NOSONAR
  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<Integer, StatusProperties>(Command.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", IllegalParameterException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Preconditions not satisfied:\n"
                + "- The SAM is locked.\n"
                + "- In P1, b7 is equal to 1.\n"
                + "- CipherEnableBit of PAR1 is 0.\n"
                + "- Dynamic mode and the outgoing challenge is unavailable.\n"
                + "- Static mode and StaticCipherEnableBit=0.",
            AccessForbiddenException.class));
    m.put(
        0x6900,
        new StatusProperties(
            "An event counter cannot be incremented.", CounterOverflowException.class));
    m.put(0x6988, new StatusProperties("Incorrect signature.", SecurityDataException.class));
    m.put(0x6A00, new StatusProperties("Incorrect P2.", IllegalParameterException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Incorrect decrypted data, including:\n"
                + "- Full ceiling record update (P2≠B8h) with DES/DESX key44 and at "
                + "least one ceiling is increased by more than 131,071.\n"
                + "- One ceiling update (P2=B8h): reference>26, or the 25 last data "
                + "bytes are not all null.",
            IncorrectInputDataException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found: deciphering key not found.", DataAccessException.class));
    STATUS_TABLE = m;
  }

  /**
   * Instantiates a new CommandWriteCeilings for writing a single ceiling value.
   *
   * @param context The command context.
   * @param targetSamContext The target SAM context.
   * @param counterNumber The number of the counter whose ceiling is to be written (in range
   *     [0..26]).
   * @param ceilingValue The ceiling value.
   * @since 0.1.0
   */
  CommandWriteCeilings(
      CommandContextDto context,
      TargetSamContextDto targetSamContext,
      int counterNumber,
      int ceilingValue) {

    super(CommandRef.WRITE_CEILINGS, 0, context);

    this.targetSamContext = targetSamContext;
    counterFileRecordNumber = -1;

    // build the plain data block to be ciphered later
    plainData[0] = targetSamContext.getSystemKeyTypeToKvcMap().get(SystemKeyType.RELOADING);
    plainData[1] = (byte) counterNumber;
    ByteArrayUtil.copyBytes(ceilingValue, plainData, 2, 3);
  }

  /**
   * Instantiates a new CommandWriteCeilings for writing a record of 9 ceiling values.
   *
   * @param context The command context.
   * @param targetSamContext The target SAM context.
   * @param counterNumber The number of the counter whose ceiling is to be written (in range
   *     [0..26]).
   * @param ceilingValue The ceiling value.
   * @param counterIncrementAccess The counter incrementation configuration.
   * @since 0.1.0
   */
  CommandWriteCeilings(
      CommandContextDto context,
      TargetSamContextDto targetSamContext,
      int counterNumber,
      int ceilingValue,
      CounterIncrementAccess counterIncrementAccess) {
    super(CommandRef.WRITE_CEILINGS, 0, context);

    this.targetSamContext = targetSamContext;
    counterFileRecordNumber = LegacySamConstant.COUNTER_TO_RECORD_LOOKUP[counterNumber];

    plainData[0] = targetSamContext.getSystemKeyTypeToKvcMap().get(SystemKeyType.RELOADING);
    addCounter(counterNumber, ceilingValue, counterIncrementAccess);
  }

  /**
   * Add a counter to be updated.
   *
   * <p>This command allows the upper layer to create a unique command when counters belongs to the
   * same record into the SAM.
   *
   * @param counterNumber The counter number (in range [0..26]).
   * @param ceilingValue The ceiling value to be written (in range [0..16777210]).
   * @param counterIncrementAccess True if free incrementing of the counter should be allowed.
   * @since 0.3.0
   */
  void addCounter(
      int counterNumber, int ceilingValue, CounterIncrementAccess counterIncrementAccess) {
    // update the plain data block to be ciphered later
    ByteArrayUtil.copyBytes(ceilingValue, plainData, (counterNumber % 9) * 3 + 1, 3);
    // keep the config into a map
    counterNumberToManualCounterIncrementAuthorizedMap.put(
        counterNumber % 9, counterIncrementAccess);
  }

  /**
   * Returns the target counter file record.
   *
   * @return -1 if the command is not targeting a record.
   * @since 0.3.0
   */
  int getCounterFileRecordNumber() {
    return counterFileRecordNumber;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  void finalizeRequest() {
    CommandContextDto controlSamContext =
        new CommandContextDto(getContext().getControlSam(), null, null);
    // add commands
    addControlSamCommand(
        new CommandSelectDiversifier(controlSamContext, targetSamContext.getSerialNumber()));
    addControlSamCommand(new CommandGiveRandom(controlSamContext, computeChallenge()));
    if (counterFileRecordNumber != -1) {
      computePlainData();
    }
    CommandSamDataCipher commandSamDataCipher =
        new CommandSamDataCipher(
            controlSamContext,
            counterFileRecordNumber,
            counterFileRecordNumber == -1
                ? CommandSamDataCipher.DataType.ONE_CEILING_VALUE
                : CommandSamDataCipher.DataType.CEILINGS_FILE_RECORD,
            plainData);
    addControlSamCommand(commandSamDataCipher);
    processControlSamCommand();
    final byte cla = (byte) 0x80;
    final byte inst = (byte) 0xD8;
    byte p1 = targetSamContext.isDynamicMode() ? (byte) 0x00 : (byte) 0x08;
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cla,
                inst,
                p1,
                counterFileRecordNumber == -1
                    ? (byte) 0xB8
                    : (byte) (0xB1 + counterFileRecordNumber),
                commandSamDataCipher.getCipheredData(),
                null)));
  }

  /** Computes the plain data block in the case of a multiple counter writing. */
  private void computePlainData() {
    short configBits = 0;
    for (int i = 0; i < 9; i++) {
      CounterIncrementAccess config = counterNumberToManualCounterIncrementAuthorizedMap.get(i);
      if (config == null) {
        config =
            getContext()
                .getTargetSam()
                .getCounterIncrementAccess((counterFileRecordNumber * 9) + i);
        if (config == null) {
          throw new IllegalStateException(
              "Unable to determine counter incrementation configuration.");
        }
      }
      if (config == CounterIncrementAccess.FREE_COUNTING_ENABLED
          && (i != 0 || counterFileRecordNumber != 0)) {
        configBits |= 1 << i;
      }
    }
    ByteArrayUtil.copyBytes(configBits, plainData, 28, 2);
  }

  /** Computes the challenge to be sent to the control SAM from the target SAM context. */
  private byte[] computeChallenge() {

    // compute the challenge
    byte[] challenge = new byte[8];
    if (targetSamContext.getSystemKeyTypeToCounterNumberMap() != null) {
      Integer reloadingKeyCounterNumber =
          targetSamContext.getSystemKeyTypeToCounterNumberMap().get(SystemKeyType.RELOADING);
      if (reloadingKeyCounterNumber != null) {
        ByteArrayUtil.copyBytes(
            targetSamContext.getCounterNumberToCounterValueMap().get(reloadingKeyCounterNumber),
            challenge,
            5,
            3);
        // increment counter
        targetSamContext
            .getCounterNumberToCounterValueMap()
            .put(
                reloadingKeyCounterNumber,
                targetSamContext.getCounterNumberToCounterValueMap().get(reloadingKeyCounterNumber)
                    + 1);
      }
    }
    return challenge;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  boolean isControlSamRequiredToFinalizeRequest() {
    return true;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  void parseResponse(ApduResponseApi apduResponse) throws CommandException {
    setResponseAndCheckStatus(apduResponse);
  }
}
