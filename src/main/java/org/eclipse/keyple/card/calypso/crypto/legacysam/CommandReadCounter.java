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

import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keypop.card.ApduResponseApi;

/**
 * Builds the Read Event Counter APDU command.
 *
 * @since 0.1.0
 */
final class CommandReadCounter extends Command {

  private final int counterFileRecordNumber;
  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<>(Command.STATUS_TABLE);
    m.put(
        0x6900,
        new StatusProperties(
            "An event counter cannot be incremented.", CounterOverflowException.class));
    m.put(0x6A00, new StatusProperties("Incorrect P2.", IllegalParameterException.class));
    m.put(0x6200, new StatusProperties("Correct execution with warning: data not signed."));
    STATUS_TABLE = m;
  }

  /**
   * Instantiate a new CmdSamReadEventCounter
   *
   * @param context The command context.
   * @param counterFileRecordNumber The number of the counter file record to read (in range [0..2].
   * @since 0.1.0
   */
  CommandReadCounter(CommandContextDto context, int counterFileRecordNumber) {

    super(CommandRef.READ_COUNTER, 48, context);
    this.counterFileRecordNumber = counterFileRecordNumber;
    byte cla = context.getTargetSam().getClassByte();
    byte p2 = (byte) (0xE1 + counterFileRecordNumber);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cla, getCommandRef().getInstructionByte(), (byte) 0x00, p2, null, (byte) 0x00)));
  }

  /**
   * Retrieves the record number of the counter file that will be modified by this command.
   *
   * @return An int.
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
    /* nothing to do */
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  boolean isControlSamRequiredToFinalizeRequest() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  void parseResponse(ApduResponseApi apduResponse) throws CommandException {
    setResponseAndCheckStatus(apduResponse);
    byte[] dataOut = apduResponse.getDataOut();
    for (int i = 0; i < 9; i++) {
      getContext()
          .getTargetSam()
          .putCounterValue(
              (counterFileRecordNumber * 9) + i,
              ByteArrayUtil.extractInt(dataOut, 8 + (3 * i), 3, false));
    }
  }
}
