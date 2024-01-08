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
import org.eclipse.keypop.calypso.crypto.legacysam.spi.LegacySamDynamicUnlockDataProviderSpi;
import org.eclipse.keypop.calypso.crypto.legacysam.spi.LegacySamStaticUnlockDataProviderSpi;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.InconsistentDataException;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.UnexpectedCommandStatusException;
import org.eclipse.keypop.card.*;
import org.eclipse.keypop.card.spi.ApduRequestSpi;
import org.eclipse.keypop.card.spi.CardSelectionExtensionSpi;
import org.eclipse.keypop.card.spi.CardSelectionRequestSpi;
import org.eclipse.keypop.card.spi.SmartCardSpi;
import org.eclipse.keypop.reader.CardReader;
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
  private static final String MSG_UNLOCK_SETTING_HAS_ALREADY_BEEN_SET =
      "A setting to unlock the SAM has already been set";
  LegacySamAdapter legacySamAdapter;
  CommandContextDto context;
  private final List<Command> commands;
  private CardReader cardReader;
  private CommandGetChallenge getChallengeCommand;

  private enum UnlockSettingType {
    UNSET,
    UNLOCK_DATA,
    STATIC_MODE_PROVIDER,
    DYNAMIC_MODE_PROVIDER
  }

  private UnlockSettingType unlockSettingType = UnlockSettingType.UNSET;
  private LegacySamStaticUnlockDataProviderSpi staticUnlockDataProvider;
  private LegacySamDynamicUnlockDataProviderSpi dynamicUnlockDataProvider;

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
    // Do not add command for now when using an Unlock Data provider
    if (unlockSettingType == UnlockSettingType.UNSET
        || unlockSettingType == UnlockSettingType.UNLOCK_DATA) {
      for (Command command : commands) {
        cardSelectionApduRequests.add(command.getApduRequest());
      }
    } else if (unlockSettingType == UnlockSettingType.DYNAMIC_MODE_PROVIDER) {
      getChallengeCommand = new CommandGetChallenge(context, 8);
      cardSelectionApduRequests.add(getChallengeCommand.getApduRequest());
    }
    if (cardSelectionApduRequests.isEmpty()) {
      return new CardSelectionRequestAdapter(null);
    }
    return new CardSelectionRequestAdapter(
        new CardRequestAdapter(cardSelectionApduRequests, false));
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public SmartCardSpi parse(CardSelectionResponseApi cardSelectionResponseApi)
      throws ParseException {
    try {
      initializeLegacySamAdapter(cardSelectionResponseApi);
      CardResponseApi cardResponse = handleUnlockCommand(cardSelectionResponseApi);
      List<ApduResponseApi> apduResponses = validateAndFetchResponses(cardResponse);
      processApduResponses(apduResponses);
    } catch (Exception e) {
      throw new ParseException("Invalid card response: " + e.getMessage(), e);
    }
    return validateAndReturnLegacySam(cardSelectionResponseApi);
  }

  /**
   * Initializes the LegacySamAdapter with the given CardSelectionResponseApi.
   *
   * @param cardSelectionResponseApi The response to the initial card selection request.
   */
  private void initializeLegacySamAdapter(CardSelectionResponseApi cardSelectionResponseApi) {
    legacySamAdapter.parseSelectionResponse(cardSelectionResponseApi);
  }

  /**
   * Handles the unlock command for a given card selection response.
   *
   * @param cardSelectionResponseApi The response to the initial card selection request.
   * @return The updated card response after handling the unlock command.
   * @throws AbstractApduException if an error occurs while handling the unlock command.
   */
  private CardResponseApi handleUnlockCommand(CardSelectionResponseApi cardSelectionResponseApi)
      throws AbstractApduException, CommandException {
    CardResponseApi cardResponse = cardSelectionResponseApi.getCardResponse();
    if (unlockSettingType == UnlockSettingType.STATIC_MODE_PROVIDER
        || unlockSettingType == UnlockSettingType.DYNAMIC_MODE_PROVIDER) {

      byte[] unlockData;
      if (unlockSettingType == UnlockSettingType.STATIC_MODE_PROVIDER) {
        unlockData = staticUnlockDataProvider.getUnlockData(legacySamAdapter.getSerialNumber());
      } else {
        getChallengeCommand.parseResponse(cardResponse.getApduResponses().get(0));
        unlockData =
            dynamicUnlockDataProvider.getUnlockData(
                legacySamAdapter.getSerialNumber(), legacySamAdapter.popChallenge());
      }

      CommandUnlock unlockCommand =
          new CommandUnlock(legacySamAdapter.getProductType(), unlockData);
      unlockCommand.getApduRequest().addSuccessfulStatusWord(SW_NOT_LOCKED);
      commands.add(0, unlockCommand);

      List<ApduRequestSpi> cardSelectionApduRequests = new ArrayList<ApduRequestSpi>();
      for (Command command : commands) {
        cardSelectionApduRequests.add(command.getApduRequest());
      }

      CardRequestAdapter cardRequest = new CardRequestAdapter(cardSelectionApduRequests, false);
      cardResponse =
          ((ProxyReaderApi) cardReader).transmitCardRequest(cardRequest, ChannelControl.KEEP_OPEN);
    }
    return cardResponse;
  }

  /**
   * Validates and fetches the APDU responses from the card response.
   *
   * @param cardResponse The card response containing the APDU responses.
   * @return The list of APDU responses.
   */
  private List<ApduResponseApi> validateAndFetchResponses(CardResponseApi cardResponse) {
    List<ApduResponseApi> apduResponses =
        cardResponse != null
            ? cardResponse.getApduResponses()
            : Collections.<ApduResponseApi>emptyList();

    if (commands.isEmpty() || commands.size() == apduResponses.size()) {
      return apduResponses;
    }
    throw new IllegalStateException("Mismatch in the number of requests/responses.");
  }

  /**
   * Processes the APDU responses returned by the SAM to all commands.
   *
   * @param apduResponses The list of APDU responses.
   */
  private void processApduResponses(List<ApduResponseApi> apduResponses) {
    if (!commands.isEmpty()) {
      parseApduResponses(commands, apduResponses);
    }
  }

  /**
   * Validates and returns the LegacySam adapter.
   *
   * @param cardSelectionResponseApi The response to the initial card selection request.
   * @return The LegacySam adapter.
   * @throws ParseException If conditions for creating a LegacySam are not met.
   */
  private SmartCardSpi validateAndReturnLegacySam(CardSelectionResponseApi cardSelectionResponseApi)
      throws ParseException {
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
        commands.get(i).parseResponse(apduResponses.get(i));
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
    if (unlockSettingType != UnlockSettingType.UNSET) {
      throw new IllegalStateException(MSG_UNLOCK_SETTING_HAS_ALREADY_BEEN_SET);
    }
    Assert.getInstance()
        .notEmpty(unlockData, "unlockData")
        .isTrue(unlockData.length() == 32, "unlock data length")
        .isHexString(unlockData, "unlockData")
        .notNull(productType, "productType");
    CommandUnlock unlockCommand = new CommandUnlock(productType, HexUtil.toByteArray(unlockData));
    unlockCommand.getApduRequest().addSuccessfulStatusWord(SW_NOT_LOCKED);
    // prepare the UNLOCK command and put it in first position
    commands.add(0, unlockCommand);
    unlockSettingType = UnlockSettingType.UNLOCK_DATA;
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
   * @since 0.5.0
   */
  @Override
  public LegacySamSelectionExtension setStaticUnlockDataProvider(
      LegacySamStaticUnlockDataProviderSpi staticUnlockDataProvider) {
    if (unlockSettingType != UnlockSettingType.UNSET) {
      throw new IllegalStateException(MSG_UNLOCK_SETTING_HAS_ALREADY_BEEN_SET);
    }
    this.staticUnlockDataProvider = staticUnlockDataProvider;
    unlockSettingType = UnlockSettingType.STATIC_MODE_PROVIDER;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.5.0
   */
  @Override
  public LegacySamSelectionExtension setDynamicUnlockDataProvider(
      LegacySamDynamicUnlockDataProviderSpi dynamicUnlockDataProvider) {
    if (unlockSettingType != UnlockSettingType.UNSET) {
      throw new IllegalStateException(MSG_UNLOCK_SETTING_HAS_ALREADY_BEEN_SET);
    }
    this.dynamicUnlockDataProvider = dynamicUnlockDataProvider;
    unlockSettingType = UnlockSettingType.DYNAMIC_MODE_PROVIDER;
    return this;
  }

  /**
   * Provides the {@link CardReader} for communicating with the SAM during the unlocking process
   * when involving a static or a dynamic unlock data providers.
   *
   * @param cardReader The card reader to be used.
   * @return The current instance.
   * @throws IllegalArgumentException If the provided argument is null.
   * @since 0.5.0
   */
  LegacySamSelectionExtension setSamCardReader(CardReader cardReader) {
    this.cardReader = cardReader;
    return this;
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
