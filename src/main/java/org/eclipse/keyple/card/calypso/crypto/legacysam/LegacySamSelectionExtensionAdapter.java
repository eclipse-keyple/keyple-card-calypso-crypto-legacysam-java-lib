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
import static org.eclipse.keyple.card.calypso.crypto.legacysam.LegacySamConstant.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.crypto.legacysam.SystemKeyType;
import org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySam;
import org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySamSelectionExtension;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.InconsistentDataException;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.UnexpectedCommandStatusException;
import org.eclipse.keypop.card.ApduResponseApi;
import org.eclipse.keypop.card.CardResponseApi;
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
  private static final String MSG_CARD_COMMAND_ERROR = "A card command error occurred ";
  LegacySamAdapter legacySamAdapter;
  CommandContextDto context;
  private final List<Command> commands;

  /**
   * Creates a {@link LegacySamSelectionExtension}.
   *
   * @since 0.1.0
   */
  LegacySamSelectionExtensionAdapter() {
    legacySamAdapter = new LegacySamAdapter(LegacySam.ProductType.SAM_C1);
    context = new CommandContextDto(legacySamAdapter, null, null);
    commands = new ArrayList<Command>();
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CardSelectionRequestSpi getCardSelectionRequest() {
    List<ApduRequestSpi> cardSelectionApduRequests = new ArrayList<ApduRequestSpi>();
    for (Command command : commands) {
      cardSelectionApduRequests.add(command.getApduRequest());
    }
    if (commands.isEmpty()) {
      return new CardSelectionRequestAdapter(null);
    } else {
      return new CardSelectionRequestAdapter(
          new CardRequestAdapter(cardSelectionApduRequests, false));
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

    CardResponseApi cardResponse = cardSelectionResponseApi.getCardResponse();
    List<ApduResponseApi> apduResponses =
        cardResponse != null
            ? cardResponse.getApduResponses()
            : Collections.<ApduResponseApi>emptyList();
    if (commands.size() != apduResponses.size()) {
      throw new ParseException("Mismatch in the number of requests/responses.");
    }
    try {
      // late initialization of the LegacySamAdapter
      legacySamAdapter.parseSelectionResponse(cardSelectionResponseApi);
      if (!commands.isEmpty()) {
        parseApduResponses(commands, apduResponses);
      }
    } catch (Exception e) {
      throw new ParseException("Invalid card response: " + e.getMessage(), e);
    }
    if (legacySamAdapter.getProductType() == LegacySam.ProductType.UNKNOWN
        && cardSelectionResponseApi.getSelectApplicationResponse() == null
        && cardSelectionResponseApi.getPowerOnData() == null) {
      throw new ParseException(
          "Unable to create a LegacySam: no power-on data and no FCI provided.");
    }
    return legacySamAdapter;
  }

  /**
   * Parses the APDU responses and updates the LegacySam image.
   *
   * @param commands The list of commands that get the responses.
   * @param apduResponses The APDU responses returned by the SAM to all commands.
   */
  private static void parseApduResponses(
      List<? extends Command> commands, List<? extends ApduResponseApi> apduResponses) {
    // If there are more responses than requests, then we are unable to fill the card image. In this
    // case we stop processing immediately because it may be a case of fraud, and we throw a
    // desynchronized exception.
    if (apduResponses.size() > commands.size()) {
      throw new InconsistentDataException(
          "The number of commands/responses does not match: nb commands = "
              + commands.size()
              + ", nb responses = "
              + apduResponses.size());
    }
    // We go through all the responses (and not the requests) because there may be fewer in the
    // case of an error that occurred in strict mode. In this case the last response will raise an
    // exception.
    for (int i = 0; i < apduResponses.size(); i++) {
      try {
        commands.get(i).setResponseAndCheckStatus(apduResponses.get(i));
      } catch (CommandException e) {
        if (e instanceof AccessForbiddenException && commands.get(i) instanceof CommandUnlock) {
          logger.warn("SAM not locked or already unlocked");
        } else {
          throw new UnexpectedCommandStatusException(
              MSG_CARD_COMMAND_ERROR
                  + "while processing responses to card commands: "
                  + commands.get(i).getCommandRef(),
              e);
        }
      }
    }
    // Finally, if no error has occurred and there are fewer responses than requests, then we
    // throw a desynchronized exception.
    if (apduResponses.size() < commands.size()) {
      throw new InconsistentDataException(
          "The number of commands/responses does not match: nb commands = "
              + commands.size()
              + ", nb responses = "
              + apduResponses.size());
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.4.0
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
    CommandUnlock unlockCommand = new CommandUnlock(productType, HexUtil.toByteArray(unlockData));
    unlockCommand.getApduRequest().addSuccessfulStatusWord(SW_NOT_LOCKED);
    // prepare the UNLOCK command and put it in first position
    commands.add(0, unlockCommand);
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

  /**
   * {@inheritDoc}
   *
   * @since 0.4.0
   */
  @Override
  public LegacySamSelectionExtension prepareReadSystemKeyParameters(SystemKeyType systemKeyType) {
    Assert.getInstance().notNull(systemKeyType, "systemKeyType");
    commands.add(new CommandReadKeyParameters(context, systemKeyType));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.4.0
   */
  @Override
  public LegacySamSelectionExtension prepareReadCounterStatus(int counterNumber) {
    Assert.getInstance()
        .isInRange(counterNumber, MIN_COUNTER_NUMBER, MAX_COUNTER_NUMBER, "counterNumber");
    for (Command command : commands) {
      if (command instanceof CommandReadCounter
          && ((CommandReadCounter) command).getCounterFileRecordNumber()
              == COUNTER_TO_RECORD_LOOKUP[counterNumber]) {
        // already scheduled
        return this;
      }
    }
    commands.add(new CommandReadCounter(context, COUNTER_TO_RECORD_LOOKUP[counterNumber]));
    commands.add(new CommandReadCounterCeiling(context, COUNTER_TO_RECORD_LOOKUP[counterNumber]));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.4.0
   */
  @Override
  public LegacySamSelectionExtension prepareReadAllCountersStatus() {
    for (int i = 0; i < 3; i++) {
      commands.add(new CommandReadCounter(context, i));
      commands.add(new CommandReadCounterCeiling(context, i));
    }
    return this;
  }
}
