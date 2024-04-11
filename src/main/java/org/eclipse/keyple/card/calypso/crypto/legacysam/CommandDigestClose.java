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
 * Builds the Digest Close APDU command.
 *
 * @since 2.0.1
 */
final class CommandDigestClose extends Command {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<>(Command.STATUS_TABLE);
    m.put(
        0x6985,
        new StatusProperties("Preconditions not satisfied.", AccessForbiddenException.class));
    STATUS_TABLE = m;
  }

  private byte[] mac;

  /**
   * Instantiates a new CommandDigestClose .
   *
   * @param context The command context.
   * @param expectedResponseLength the expected response length.
   * @since 2.0.1
   */
  CommandDigestClose(DtoAdapters.CommandContextDto context, int expectedResponseLength) {

    super(CommandRef.DIGEST_CLOSE, expectedResponseLength, context);

    setApduRequest(
        new DtoAdapters.ApduRequestAdapter(
            ApduUtil.build(
                context.getTargetSam().getClassByte(),
                getCommandRef().getInstructionByte(),
                (byte) 0x00,
                (byte) 0x00,
                null,
                (byte) expectedResponseLength)));
  }

  /**
   * Gets the MAC computed by the SAM.
   *
   * @return The half session signature
   * @since 2.0.1
   */
  byte[] getMac() {
    return mac;
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
    mac = apduResponse.getDataOut();
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
