/* **************************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://calypsonet.org/
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
 * Builds the Card Cipher PIN APDU command.
 *
 * @since 2.0.1
 */
final class CommandCardCipherPin extends Command {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<Integer, StatusProperties>(Command.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", IllegalParameterException.class));
    m.put(
        0x6900,
        new StatusProperties(
            "An event counter cannot be incremented.", CounterOverflowException.class));
    m.put(
        0x6985,
        new StatusProperties("Preconditions not satisfied.", AccessForbiddenException.class));
    m.put(0x6A00, new StatusProperties("Incorrect P1 or P2", IllegalParameterException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found: ciphering key not found", DataAccessException.class));
    STATUS_TABLE = m;
  }

  private byte[] cipheredData;

  /**
   * Instantiates a new CommandCardCipherPin and generate the ciphered data for a "Verify PIN" or
   * Change PIN card command.
   *
   * <p>In the case of a PIN verification, only the current PIN must be provided (newPin must be set
   * to null).
   *
   * <p>In the case of a PIN update, the current and new PINs must be provided.
   *
   * @param context The command context.
   * @param cipheringKif the KIF of the key used to encipher the PIN data.
   * @param cipheringKvc the KVC of the key used to encipher the PIN data.
   * @param currentPin the current PIN (a 4-byte byte array).
   * @param newPin the new PIN (a 4-byte byte array if the operation in progress is a PIN update,
   *     null if the operation in progress is a PIN verification)
   * @since 2.0.1
   */
  CommandCardCipherPin(
      DtoAdapters.CommandContextDto context,
      byte cipheringKif,
      byte cipheringKvc,
      byte[] currentPin,
      byte[] newPin) {

    super(CommandRef.CARD_CIPHER_PIN, 0, context);

    if (currentPin == null || currentPin.length != 4) {
      throw new IllegalArgumentException("Bad current PIN value.");
    }

    if (newPin != null && newPin.length != 4) {
      throw new IllegalArgumentException("Bad new PIN value.");
    }

    byte cla = context.getTargetSam().getClassByte();

    byte p1;
    byte p2;
    byte[] data;

    if (newPin == null) {
      // no new PIN is provided, we consider it's a PIN verification
      p1 = (byte) 0x80;
      data = new byte[6];
    } else {
      // a new PIN is provided, we consider it's a PIN update
      p1 = (byte) 0x40;
      data = new byte[10];
      System.arraycopy(newPin, 0, data, 6, 4);
    }
    p2 = (byte) 0xFF; // KIF and KVC in incoming data

    data[0] = cipheringKif;
    data[1] = cipheringKvc;

    System.arraycopy(currentPin, 0, data, 2, 4);

    setApduRequest(
        new DtoAdapters.ApduRequestAdapter(
            ApduUtil.build(cla, getCommandRef().getInstructionByte(), p1, p2, data, null)));
  }

  /**
   * Gets the 8 bytes of ciphered data.
   *
   * @return The ciphered data byte array
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
