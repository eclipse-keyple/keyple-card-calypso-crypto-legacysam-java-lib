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
import org.eclipse.keypop.card.ApduResponseApi;

/**
 * Builds the Write Key APDU command.
 *
 * @since 0.9.0
 */
final class CommandWriteKey extends Command {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<>(Command.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc", IllegalParameterException.class));
    m.put(
        0x6900,
        new StatusProperties(
            "An event counter cannot be incremented", CounterOverflowException.class));
    m.put(
        0x6985,
        new StatusProperties("Preconditions not satisfied", AccessForbiddenException.class));
    m.put(0x6988, new StatusProperties("Incorrect signature", SecurityDataException.class));
    m.put(0x6A00, new StatusProperties("P1 or P2 incorrect", IllegalParameterException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Incorrect plain or decrypted data", IncorrectInputDataException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found: deciphering key not found", DataAccessException.class));
    m.put(
        0x6A87,
        new StatusProperties("Lc inconsistent with P1 or P2", IncorrectInputDataException.class));
    STATUS_TABLE = m;
  }

  /**
   * Instantiates a new CommandWriteKey.
   *
   * @param context The command context.
   * @param targetSamContext The target SAM context.
   * @param keyReference the key reference (P2).
   * @param keyData the key data.
   * @since 0.9.0
   */
  CommandWriteKey(
      CommandContextDto context,
      TargetSamContextDto targetSamContext,
      byte keyReference,
      byte[] keyData) {

    super(CommandRef.WRITE_KEY, 0, context);

    byte cla = context.getTargetSam().getClassByte();

    if (keyData == null) {
      throw new IllegalArgumentException("Key data null!");
    }

    if (keyData.length != 48 && keyData.length != 80) {
      throw new IllegalArgumentException("Key data should be between 40 or 80 bytes long!");
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cla,
                getCommandRef().getInstructionByte(),
                (byte) (targetSamContext.isDynamicMode() ? 0x08 : 0x00),
                keyReference,
                keyData,
                null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  void finalizeRequest() {
    /* nothing to do */
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  boolean isControlSamRequiredToFinalizeRequest() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  void parseResponse(ApduResponseApi apduResponse) throws CommandException {
    setResponseAndCheckStatus(apduResponse);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }
}
