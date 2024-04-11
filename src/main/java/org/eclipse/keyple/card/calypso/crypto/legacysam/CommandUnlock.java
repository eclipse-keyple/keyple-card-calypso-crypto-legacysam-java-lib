/* **************************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://calypsonet.org/
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
import org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySam;
import org.eclipse.keypop.card.ApduResponseApi;

/**
 * Builds the "Unlock" APDU command.
 *
 * @since 0.1.0
 */
final class CommandUnlock extends Command {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<>(Command.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", IllegalParameterException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Preconditions not satisfied (SAM not locked?).", AccessForbiddenException.class));
    m.put(0x6988, new StatusProperties("Incorrect UnlockData.", SecurityDataException.class));
    STATUS_TABLE = m;
  }

  /**
   * LegacySamCardSelectorBuilder constructor
   *
   * @param productType the SAM product type.
   * @param unlockData the unlocked data.
   * @since 0.1.0
   */
  CommandUnlock(LegacySam.ProductType productType, byte[] unlockData) {

    super(CommandRef.UNLOCK, 0, null);

    byte cla = productType == LegacySam.ProductType.SAM_S1DX ? (byte) 0x94 : (byte) 0x80;
    byte p1 = 0x00;
    byte p2 = 0x00;

    if (unlockData == null) {
      throw new IllegalArgumentException("Unlock data null!");
    }

    if (unlockData.length != 8 && unlockData.length != 16) {
      throw new IllegalArgumentException("Unlock data should be 8 ou 16 bytes long!");
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, getCommandRef().getInstructionByte(), p1, p2, unlockData, null)));
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
