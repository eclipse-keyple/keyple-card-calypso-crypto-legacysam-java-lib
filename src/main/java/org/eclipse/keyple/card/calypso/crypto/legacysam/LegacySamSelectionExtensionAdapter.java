/* **************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/
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

import java.util.ArrayList;
import java.util.List;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.crypto.legacysam.SystemKeyType;
import org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySam;
import org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySamSelectionExtension;
import org.eclipse.keypop.card.ApduResponseApi;
import org.eclipse.keypop.card.CardSelectionResponseApi;
import org.eclipse.keypop.card.ParseException;
import org.eclipse.keypop.card.spi.ApduRequestSpi;
import org.eclipse.keypop.card.spi.CardSelectionExtensionSpi;
import org.eclipse.keypop.card.spi.CardSelectionRequestSpi;
import org.eclipse.keypop.card.spi.SmartCardSpi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapter of {@link LegacySamSelectionExtension}.
 *
 * <p>If not specified, the SAM product type used for unlocking is {@link
 * LegacySam.ProductType#SAM_C1}.
 *
 * @since 0.1.0
 */
final class LegacySamSelectionExtensionAdapter
    implements LegacySamSelectionExtension, CardSelectionExtensionSpi {

  private static final Logger logger =
      LoggerFactory.getLogger(LegacySamSelectionExtensionAdapter.class);
  private static final int SW_NOT_LOCKED = 0x6985;
  private CommandUnlock unlockCommand;

  /**
   * Creates a {@link LegacySamSelectionExtension}.
   *
   * @since 0.1.0
   */
  LegacySamSelectionExtensionAdapter() {}

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CardSelectionRequestSpi getCardSelectionRequest() {

    // prepare the UNLOCK command if unlock data has been defined
    if (unlockCommand != null) {
      List<ApduRequestSpi> cardSelectionApduRequests = new ArrayList<ApduRequestSpi>();
      cardSelectionApduRequests.add(
          unlockCommand.getApduRequest().addSuccessfulStatusWord(SW_NOT_LOCKED));
      return new CardSelectionRequestAdapter(
          new CardRequestAdapter(cardSelectionApduRequests, false));
    } else {
      return new CardSelectionRequestAdapter(null);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public SmartCardSpi parse(CardSelectionResponseApi cardSelectionResponseApi)
      throws ParseException {
    if (unlockCommand != null) {
      // an unlock command has been requested
      if (cardSelectionResponseApi.getCardResponse() == null
          || cardSelectionResponseApi.getCardResponse().getApduResponses().isEmpty()) {
        throw new ParseException("Mismatch in the number of requests/responses");
      }
      // check the SAM response to the unlock command
      ApduResponseApi apduResponse =
          cardSelectionResponseApi.getCardResponse().getApduResponses().get(0);
      try {
        unlockCommand.setResponseAndCheckStatus(apduResponse);
      } catch (AccessForbiddenException e) {
        logger.warn("SAM not locked or already unlocked");
      } catch (CommandException e) {
        throw new ParseException("An exception occurred while parsing the SAM response.", e);
      }
    }
    try {
      return new LegacySamAdapter(cardSelectionResponseApi);
    } catch (RuntimeException e) {
      throw new ParseException("An exception occurred while parsing the SAM response.", e);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 1.0.0
   */
  @Override
  public LegacySamSelectionExtension setUnlockData(
      String unlockData, LegacySam.ProductType productType) {
    Assert.getInstance()
        .notEmpty(unlockData, "unlockData")
        .isTrue(
            unlockData.length() == 16 || unlockData.length() == 32,
            "unlock data length == 16 or 32")
        .isHexString(unlockData, "unlockData")
        .notNull(productType, "productType");
    unlockCommand = new CommandUnlock(productType, HexUtil.toByteArray(unlockData));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public LegacySamSelectionExtension setUnlockData(String unlockData) {
    return setUnlockData(unlockData, LegacySam.ProductType.SAM_C1);
  }

  @Override
  public LegacySamSelectionExtension prepareReadSystemKeyParameters(SystemKeyType systemKeyType) {
    return null;
  }

  @Override
  public LegacySamSelectionExtension prepareReadCounterStatus(int i) {
    return null;
  }

  @Override
  public LegacySamSelectionExtension prepareReadAllCountersStatus() {
    return null;
  }
}
