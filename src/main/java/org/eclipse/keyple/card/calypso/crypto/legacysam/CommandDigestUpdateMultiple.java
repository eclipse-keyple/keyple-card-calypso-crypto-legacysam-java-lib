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
 * Builds the SAM Digest Update Multiple APDU command.
 *
 * @since 2.0.1
 */
final class CommandDigestUpdateMultiple extends Command {

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
            "Incorrect value in the incoming data: incorrect structure",
            IncorrectInputDataException.class));
    m.put(0x6B00, new StatusProperties("Incorrect P1", IllegalParameterException.class));
    STATUS_TABLE = m;
  }

  /**
   * Constructor
   *
   * @param context The command context.
   * @param digestData the digest data.
   * @since 2.0.1
   */
  CommandDigestUpdateMultiple(DtoAdapters.CommandContextDto context, byte[] digestData) {
    super(CommandRef.DIGEST_UPDATE_MULTIPLE, 0, context);

    byte cla = context.getTargetSam().getClassByte();
    byte p1 = (byte) 0x80;
    byte p2 = (byte) 0x00;

    if (digestData == null || digestData.length > 255) {
      throw new IllegalArgumentException(
          "Digest data is null or too long. Expected 0-255 bytes, got "
              + (digestData != null ? digestData.length : "null"));
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
