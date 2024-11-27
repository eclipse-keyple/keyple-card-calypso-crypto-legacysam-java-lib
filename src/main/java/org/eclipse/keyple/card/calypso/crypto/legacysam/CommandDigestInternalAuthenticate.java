/* **************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/
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
 * Builds the Digest Internal Authenticate APDU command.
 *
 * <p>This outgoing command generates the signature to send to the card in a Manage Secure Session
 * command during a secure session in Extended Mode.
 *
 * @since 2.3.1
 */
final class CommandDigestInternalAuthenticate extends Command {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<>(Command.STATUS_TABLE);
    m.put(
        0x6985,
        new StatusProperties(
            "Preconditions not satisfied:\n"
                + "- Session not in \"ongoing\" state.\n"
                + "- Session not opened in Extended mode.\n"
                + "- Session opened in Verification mode.\n"
                + "- Authentication not allowed by the key (not an AES key).\n"
                + "- 250th occurrence since session start",
            AccessForbiddenException.class));
    m.put(0x6B00, new StatusProperties("Incorrect P1", IllegalParameterException.class));

    STATUS_TABLE = m;
  }

  private byte[] terminalSignature;

  /**
   * Constructor
   *
   * @param context The command context.
   * @since 2.3.1
   */
  CommandDigestInternalAuthenticate(DtoAdapters.CommandContextDto context) {

    super(CommandRef.DIGEST_INTERNAL_AUTHENTICATE, 8, context);

    setApduRequest(
        new DtoAdapters.ApduRequestAdapter(
            ApduUtil.build(
                context.getTargetSam().getClassByte(),
                getCommandRef().getInstructionByte(),
                (byte) 0x80,
                (byte) 0x00,
                null,
                (byte) 8)));
  }

  /**
   * Gets the terminal signature.
   *
   * @return An 8-byte byte array.
   * @since 2.3.1
   */
  byte[] getTerminalSignature() {
    return terminalSignature;
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
    terminalSignature = apduResponse.getDataOut();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }
}
