/* **************************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/
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
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * Builds the "Give Random" APDU command.
 *
 * @since 0.3.0
 */
final class CmdSamGiveRandom extends Command {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<Integer, StatusProperties>(Command.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", IllegalParameterException.class));
    STATUS_TABLE = m;
  }

  /**
   * Instantiates a new CmdSamGiveRandom.
   *
   * @param context The SAM transaction context.
   * @param random the random data.
   * @throws IllegalArgumentException If the random data is null or has a length not equal to 8.
   * @since 0.3.0
   */
  CmdSamGiveRandom(CommandContextDto context, byte[] random) {
    super(CommandRef.GIVE_RANDOM, 0, context);

    byte cla = context.getTargetSam().getClassByte();
    byte p1 = (byte) 0x00;
    byte p2 = (byte) 0x00;

    if (random == null || random.length != 8) {
      throw new IllegalArgumentException("Random value should be an 8 bytes long");
    }
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, getCommandRef().getInstructionByte(), p1, p2, random, null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  void finalizeRequest() {}

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
   * @since 0.3.0
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }
}
