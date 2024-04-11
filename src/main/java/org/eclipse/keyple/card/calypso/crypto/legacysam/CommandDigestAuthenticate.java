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
 * Builds the Digest Authenticate APDU command.
 *
 * @since 2.0.1
 */
final class CommandDigestAuthenticate extends Command {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<>(Command.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", IllegalParameterException.class));
    m.put(
        0x6985,
        new StatusProperties("Preconditions not satisfied.", AccessForbiddenException.class));
    m.put(0x6988, new StatusProperties("Incorrect signature.", SecurityDataException.class));
    STATUS_TABLE = m;
  }

  /**
   * Instantiates a new CommandDigestAuthenticate .
   *
   * @param context The command context.
   * @param signature the signature.
   * @throws IllegalArgumentException If the signature is null or has a wrong length.
   * @since 2.0.1
   */
  CommandDigestAuthenticate(DtoAdapters.CommandContextDto context, byte[] signature) {

    super(CommandRef.DIGEST_AUTHENTICATE, 0, context);

    if (signature == null) {
      throw new IllegalArgumentException("Signature can't be null");
    }
    if (signature.length != 4 && signature.length != 8 && signature.length != 16) {
      throw new IllegalArgumentException(
          "Signature is not the right length : length is " + signature.length);
    }
    byte cla = context.getTargetSam().getClassByte();
    byte p1 = 0x00;
    byte p2 = (byte) 0x00;

    setApduRequest(
        new DtoAdapters.ApduRequestAdapter(
            ApduUtil.build(cla, getCommandRef().getInstructionByte(), p1, p2, signature, null)));
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
