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

/**
 * Builds the Get Challenge APDU command.
 *
 * @since 0.1.0
 */
final class CommandGetChallenge extends Command {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<Integer, StatusProperties>(Command.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Le.", IllegalParameterException.class));
    STATUS_TABLE = m;
  }

  /**
   * Instantiates a new CmdSamGetChallenge.
   *
   * @param legacySam The Calypso legacy SAM.
   * @param expectedResponseLength the expected response length.
   * @since 0.1.0
   */
  CommandGetChallenge(LegacySamAdapter legacySam, int expectedResponseLength) {

    super(CommandRef.GET_CHALLENGE, expectedResponseLength, legacySam);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                legacySam.getClassByte(),
                getCommandRef().getInstructionByte(),
                (byte) 0,
                (byte) 0,
                null,
                (byte) expectedResponseLength)));
  }

  /**
   * Gets the challenge.
   *
   * @return the challenge
   * @since 0.1.0
   */
  byte[] getChallenge() {
    return isSuccessful() ? getApduResponse().getDataOut() : null;
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
