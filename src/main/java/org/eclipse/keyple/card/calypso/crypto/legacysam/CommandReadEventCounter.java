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
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.ByteArrayUtil;

/**
 * Builds the Read Event Counter APDU command.
 *
 * @since 0.1.0
 */
final class CommandReadEventCounter extends Command {

  /** Event counter operation type */
  enum CounterOperationType {
    /** Single counter */
    READ_SINGLE_COUNTER,
    /** Counter record */
    READ_COUNTER_RECORD
  }

  private final CounterOperationType counterOperationType;
  private final int firstEventCounterNumber;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<Integer, StatusProperties>(Command.STATUS_TABLE);
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
   * @param legacySam The Calypso legacy SAM.
   * @param counterOperationType the counter operation type.
   * @param target the counter index (0-26) if READ_SINGLE_COUNTER, the record index (1-3) if
   *     READ_COUNTER_RECORD.
   * @since 0.1.0
   */
  CommandReadEventCounter(
      LegacySamAdapter legacySam, CounterOperationType counterOperationType, int target) {

    super(CommandRef.READ_EVENT_COUNTER, 48, legacySam);

    byte cla = legacySam.getClassByte();
    byte p2;
    this.counterOperationType = counterOperationType;
    if (counterOperationType == CounterOperationType.READ_SINGLE_COUNTER) {
      this.firstEventCounterNumber = target;
      p2 = (byte) (0x81 + target);
    } else {
      this.firstEventCounterNumber = (target - 1) * 9;
      p2 = (byte) (0xE0 + target);
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cla, getCommandRef().getInstructionByte(), (byte) 0x00, p2, null, (byte) 0x00)));
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
   * @since 0.1.0
   */
  @Override
  void parseApduResponse(ApduResponseApi apduResponse) throws CommandException {
    super.parseApduResponse(apduResponse);
    byte[] dataOut = apduResponse.getDataOut();
    if (counterOperationType == CounterOperationType.READ_SINGLE_COUNTER) {
      getLegacySam().putEventCounter(dataOut[8], ByteArrayUtil.extractInt(dataOut, 9, 3, false));
    } else {
      for (int i = 0; i < 9; i++) {
        getLegacySam()
            .putEventCounter(
                firstEventCounterNumber + i,
                ByteArrayUtil.extractInt(dataOut, 8 + (3 * i), 3, false));
      }
    }
  }
}
