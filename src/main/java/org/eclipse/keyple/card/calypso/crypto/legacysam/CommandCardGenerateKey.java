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

import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keypop.card.ApduResponseApi;

/**
 * Builds the Give Random APDU command.
 *
 * @since 2.0.1
 */
final class CommandCardGenerateKey extends Command {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<>(Command.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc", IllegalParameterException.class));
    m.put(
        0x6985,
        new StatusProperties("Preconditions not satisfied", AccessForbiddenException.class));
    m.put(0x6A00, new StatusProperties("Incorrect P1 or P2", IllegalParameterException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Incorrect incoming data: unknown or incorrect format",
            IncorrectInputDataException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found: ciphering key or key to cipher not found",
            DataAccessException.class));
    STATUS_TABLE = m;
  }

  private byte[] cipheredData;

  /**
   * Constructor
   *
   * <p>If bot KIF and KVC of the ciphering are equal to 0, the source key is ciphered with the null
   * key.
   *
   * @param context The command context.
   * @param cipheringKif The KIF of the ciphering key.
   * @param cipheringKvc The KVC of the ciphering key.
   * @param sourceKif The KIF of the source key.
   * @param sourceKvc The KVC of the source key.
   * @since 2.0.1
   */
  CommandCardGenerateKey(
      DtoAdapters.CommandContextDto context,
      byte cipheringKif,
      byte cipheringKvc,
      byte sourceKif,
      byte sourceKvc) {

    super(CommandRef.CARD_GENERATE_KEY, 0, context);

    byte cla = context.getTargetSam().getClassByte();

    byte p1;
    byte p2;
    byte[] data;

    if (cipheringKif == 0 && cipheringKvc == 0) {
      // case where the source key is ciphered by the null key
      p1 = (byte) 0xFF;
      p2 = (byte) 0x00;

      data = new byte[3];
      data[0] = sourceKif;
      data[1] = sourceKvc;
      data[2] = (byte) 0x90;
    } else {
      p1 = (byte) 0xFF;
      p2 = (byte) 0xFF;

      data = new byte[5];
      data[0] = cipheringKif;
      data[1] = cipheringKvc;
      data[2] = sourceKif;
      data[3] = sourceKvc;
      data[4] = (byte) 0x90;
    }

    setApduRequest(
        new DtoAdapters.ApduRequestAdapter(
            ApduUtil.build(cla, getCommandRef().getInstructionByte(), p1, p2, data, null)));
  }

  /**
   * Gets the 32 bytes of ciphered data.
   *
   * @return the ciphered data byte array or null if the operation failed
   * @since 2.0.1
   */
  byte[] getCipheredData() {
    return cipheredData;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.4.0
   */
  @Override
  void finalizeRequest() {
    /* nothing to do */
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.4.0
   */
  @Override
  boolean isControlSamRequiredToFinalizeRequest() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.4.0
   */
  @Override
  void parseResponse(ApduResponseApi apduResponse) throws CommandException {
    setResponseAndCheckStatus(apduResponse);
    cipheredData = apduResponse.getDataOut();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.1
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }
}
