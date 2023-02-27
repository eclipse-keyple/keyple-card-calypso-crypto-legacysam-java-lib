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

import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.calypso.crypto.legacysam.SystemKeyType;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * Builds the "Read Key Parameters" SAM command.
 *
 * @since 0.3.0
 */
final class CommandReadKeyParameters extends Command {
  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<Integer, StatusProperties>(Command.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", IllegalParameterException.class));
    m.put(
        0x6900,
        new StatusProperties(
            "An event counter cannot be incremented.", CounterOverflowException.class));
    m.put(0x6A00, new StatusProperties("Incorrect P2.", IllegalParameterException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found: key to read not found.", DataAccessException.class));
    m.put(0x6200, new StatusProperties("Correct execution with warning: data not signed.", null));
    STATUS_TABLE = m;
  }

  private SystemKeyType systemKeyType;

  /**
   * Instantiates a new instance to read the parameters of a system key.
   *
   * @param context The command context.
   * @param systemKeyType The type of the system key.
   * @since 0.3.0
   */
  CommandReadKeyParameters(CommandContextDto context, SystemKeyType systemKeyType) {

    super(CommandRef.READ_KEY_PARAMETERS, 32, context);

    byte cla = context.getTargetSam().getClassByte();
    byte inst = getCommandRef().getInstructionByte();
    final byte p1 = 0;
    byte p2;
    this.systemKeyType = systemKeyType;
    switch (this.systemKeyType) {
      case PERSONALIZATION:
        p2 = (byte) 0xC1;
        break;
      case KEY_MANAGEMENT:
        p2 = (byte) 0xC2;
        break;
      case RELOADING:
        p2 = (byte) 0xC3;
        break;
      case AUTHENTICATION:
        p2 = (byte) 0xC4;
        break;
      default:
        throw new IllegalStateException("Unexpected value: " + systemKeyType);
    }
    byte[] dataIn = {0x00, 0x00};

    setApduRequest(new ApduRequestAdapter(ApduUtil.build(cla, inst, p1, p2, dataIn, null)));
  }

  /**
   * Instantiates a new instance to read the parameters of a key identified by its KIF and KVC.
   *
   * @param context The command context.
   * @param kif The KIF of the key.
   * @param kvc The KIF of the key.
   * @since 0.3.0
   */
  CommandReadKeyParameters(CommandContextDto context, byte kif, byte kvc) {

    super(CommandRef.READ_KEY_PARAMETERS, 32, context);

    byte cla = context.getTargetSam().getClassByte();
    byte inst = getCommandRef().getInstructionByte();
    final byte p1 = 0;
    final byte p2 = (byte) 0xF0;
    byte[] dataIn = {kif, kvc};

    setApduRequest(new ApduRequestAdapter(ApduUtil.build(cla, inst, p1, p2, dataIn, null)));
  }

  /**
   * Instantiates a new instance to read the parameters of a key identified by its record number.
   *
   * @param context The command context.
   * @param recordNumber the record number
   * @since 0.3.0
   */
  CommandReadKeyParameters(CommandContextDto context, int recordNumber) {

    super(CommandRef.READ_KEY_PARAMETERS, 32, context);

    byte cla = context.getTargetSam().getClassByte();
    byte inst = getCommandRef().getInstructionByte();
    final byte p1 = 0;
    byte p2 = (byte) recordNumber;
    byte[] dataIn = {0x00, 0x00};

    setApduRequest(new ApduRequestAdapter(ApduUtil.build(cla, inst, p1, p2, dataIn, null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
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
    if (systemKeyType != null) {
      byte[] keyParameter = new byte[13];
      System.arraycopy(apduResponse.getApdu(), 8, keyParameter, 0, 13);
      getContext()
          .getTargetSam()
          .setSystemKeyParameter(systemKeyType, new KeyParameterAdapter(keyParameter));
    }
  }
}
