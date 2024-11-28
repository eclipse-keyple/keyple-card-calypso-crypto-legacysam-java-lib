/* **************************************************************************************
 * Copyright (c) 2018 Calypso Networks Association https://calypsonet.org/
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
 * Builds the Digest Update APDU command.
 *
 * <p>This command have to be sent twice for each command executed during a session. First time for
 * the command sent and second time for the answer received.
 *
 * @since 2.0.1
 */
final class CommandDigestUpdate extends Command {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<>(Command.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc", IllegalParameterException.class));
    m.put(
        0x6985,
        new StatusProperties("Preconditions not satisfied", AccessForbiddenException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Incorrect value in the incoming data: session in Rev.3.2 mode with encryption/decryption active and not enough data (less than 5 bytes for and odd occurrence or less than 2 bytes for an even occurrence)",
            IncorrectInputDataException.class));
    m.put(0x6B00, new StatusProperties("Incorrect P1 or P2", IllegalParameterException.class));
    STATUS_TABLE = m;
  }

  private byte[] processedData;

  /**
   * Constructor
   *
   * @param context The command context.
   * @param encryptedSession the encrypted session flag, true if encrypted.
   * @param digestData all bytes from command sent by the card or response from the command.
   * @throws IllegalArgumentException If the digest data is null or has a length &gt; 255
   * @since 2.0.1
   */
  CommandDigestUpdate(
      DtoAdapters.CommandContextDto context, boolean encryptedSession, byte[] digestData) {

    super(CommandRef.DIGEST_UPDATE, 0, context);

    byte cla = context.getTargetSam().getClassByte();
    byte p1 = (byte) 0x00;
    byte p2 = encryptedSession ? (byte) 0x80 : (byte) 0x00;

    if (digestData == null || digestData.length > 255) {
      throw new IllegalArgumentException("Digest data null or too long!");
    }

    setApduRequest(
        new DtoAdapters.ApduRequestAdapter(
            ApduUtil.build(cla, getCommandRef().getInstructionByte(), p1, p2, digestData, null)));
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
    processedData = apduResponse.getDataOut();
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

  /**
   * Return the command output.
   *
   * @return A not null byte array.
   * @since 0.4.0
   */
  byte[] getProcessedData() {
    return processedData;
  }
}
