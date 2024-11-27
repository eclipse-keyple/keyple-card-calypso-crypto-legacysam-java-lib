/* **************************************************************************************
 * Copyright (c) 2024 Calypso Networks Association https://calypsonet.org/
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
import static org.eclipse.keyple.card.calypso.crypto.legacysam.LegacySamConstants.SAM_PARAMETERS_LENGTH;

import java.util.*;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keypop.card.ApduResponseApi;

/**
 * Builds the Read Parameters APDU command.
 *
 * @since 0.9.0
 */
final class CommandReadParameters extends Command {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;
  private static final int SW_DATA_NOT_SIGNED_WARNING = 0x6200;

  static {
    Map<Integer, StatusProperties> m = new HashMap<>(Command.STATUS_TABLE);
    m.put(
        0x6900,
        new StatusProperties(
            "An event counter cannot be incremented", CounterOverflowException.class));
    m.put(0x6A00, new StatusProperties("Incorrect P1 or P2", IllegalParameterException.class));
    m.put(0x6200, new StatusProperties("Correct execution with warning: data not signed"));
    STATUS_TABLE = m;
  }

  /**
   * Constructor
   *
   * @param context The command context.
   * @since 0.9.0
   */
  CommandReadParameters(CommandContextDto context) {

    super(CommandRef.READ_PARAMETERS, 48, context);

    byte cla = context.getTargetSam().getClassByte();
    final byte p1 = 0x00;
    final byte p2 = (byte) (0xA0);

    setApduRequest(
        new ApduRequestAdapter(
                ApduUtil.build(
                    cla, getCommandRef().getInstructionByte(), p1, p2, null, (byte) 0x00))
            .addSuccessfulStatusWord(SW_DATA_NOT_SIGNED_WARNING));
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
    byte[] keyParameter = new byte[SAM_PARAMETERS_LENGTH];
    System.arraycopy(apduResponse.getApdu(), 8, keyParameter, 0, SAM_PARAMETERS_LENGTH);
    getContext().getTargetSam().setSamParameters(new SamParametersAdapter(keyParameter));
  }
}
