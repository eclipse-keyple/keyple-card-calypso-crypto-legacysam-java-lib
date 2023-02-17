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

import java.util.*;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.ByteArrayUtil;

/**
 * Builds the Read Ceilings APDU command.
 *
 * @since 0.1.0
 */
final class CommandReadCounterCeiling extends Command {

  /** Ceiling operation type */
  enum CeilingsOperationType {
    /** Single ceiling */
    READ_SINGLE_CEILING,
    /** Ceiling record */
    READ_CEILING_RECORD
  }

  private final int ceilingFileRecordNumber;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<Integer, StatusProperties>(Command.STATUS_TABLE);
    m.put(
        0x6900,
        new StatusProperties(
            "An event counter cannot be incremented.", CounterOverflowException.class));
    m.put(0x6A00, new StatusProperties("Incorrect P1 or P2.", IllegalParameterException.class));
    m.put(0x6200, new StatusProperties("Correct execution with warning: data not signed."));
    STATUS_TABLE = m;
  }

  /**
   * Instantiates a new CmdSamReadCeilings.
   *
   * @param context The SAM transaction context.
   * @param ceilingFileRecordNumber The number of the counter file record to read (in range [0..2].
   * @since 0.1.0
   */
  CommandReadCounterCeiling(CommandContextDto context, int ceilingFileRecordNumber) {

    super(CommandRef.READ_CEILINGS, 48, context);

    byte cla = context.getTargetSam().getClassByte();
    byte p1 = (byte) 0x00;
    byte p2 = (byte) (0xB1 + ceilingFileRecordNumber);
    this.ceilingFileRecordNumber = ceilingFileRecordNumber;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, getCommandRef().getInstructionByte(), p1, p2, null, (byte) 0x00)));
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
    LegacySamAdapter targetSam = getContext().getTargetSam();
    short counterIncrementConfig = (short) ByteArrayUtil.extractInt(dataOut, 27, 2, false);
    for (int i = 0; i < 9; i++) {
      targetSam.putCounterCeilingValue(
          (this.ceilingFileRecordNumber * 9) + i,
          ByteArrayUtil.extractInt(dataOut, 8 + (3 * i), 3, false));
      targetSam.putCounterIncrementConfiguration(
          (this.ceilingFileRecordNumber * 9) + i, (counterIncrementConfig & (1 << i)) != 0);
    }
  }
}
