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

import static org.eclipse.keyple.card.calypso.crypto.legacysam.DtoAdapters.*;

import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keypop.card.ApduResponseApi;

/**
 * Builds the SAM Select Diversifier APDU command.
 *
 * @since 0.1.0
 */
final class CommandSelectDiversifier extends Command {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<Integer, StatusProperties>(Command.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", IllegalParameterException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Preconditions not satisfied: the SAM is locked.", AccessForbiddenException.class));
    STATUS_TABLE = m;
  }

  /**
   * Instantiates a new CommandSelectDiversifier.
   *
   * @param context The command context.
   * @param diversifier The key diversifier.
   * @since 0.1.0
   */
  CommandSelectDiversifier(CommandContextDto context, byte[] diversifier) {

    super(CommandRef.SELECT_DIVERSIFIER, 0, context);

    // Format the diversifier on 4 or 8 bytes if needed.
    if (diversifier.length != 4 && diversifier.length != 8) {
      int newLength = diversifier.length < 4 ? 4 : 8;
      byte[] tmp = new byte[newLength];
      System.arraycopy(diversifier, 0, tmp, newLength - diversifier.length, diversifier.length);
      diversifier = tmp;
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                context.getTargetSam().getClassByte(),
                getCommandRef().getInstructionByte(),
                (byte) 0,
                (byte) 0,
                diversifier,
                null)));
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
}
