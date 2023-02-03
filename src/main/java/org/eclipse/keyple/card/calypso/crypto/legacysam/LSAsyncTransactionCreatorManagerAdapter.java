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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.calypsonet.terminal.calypso.crypto.legacysam.SystemKeyType;
import org.calypsonet.terminal.calypso.crypto.legacysam.transaction.*;
import org.calypsonet.terminal.card.*;
import org.calypsonet.terminal.card.spi.ApduRequestSpi;
import org.calypsonet.terminal.card.spi.CardRequestSpi;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keyple.core.util.json.JsonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LSAsyncTransactionCreatorManagerAdapter implements LSAsyncTransactionCreatorManager {

  private static final Logger logger =
      LoggerFactory.getLogger(LSAsyncTransactionCreatorManagerAdapter.class);

  /* Prefix/suffix used to compose exception messages */
  private static final String MSG_SAM_READER_COMMUNICATION_ERROR =
      "A communication error with the SAM reader occurred ";
  private static final String MSG_SAM_COMMUNICATION_ERROR =
      "A communication error with the SAM occurred ";
  private static final String MSG_SAM_COMMAND_ERROR = "A SAM command error occurred ";
  private static final String MSG_SAM_INCONSISTENT_DATA =
      "The number of SAM commands/responses does not match: nb commands = ";
  private static final String MSG_SAM_NB_RESPONSES = ", nb responses = ";
  private static final String MSG_WHILE_TRANSMITTING_COMMANDS = "while transmitting commands.";

  /* Final fields */
  private final TargetSamContextDto targetSamContext;
  private final ProxyReaderApi controlSamReader;
  private final LegacySamAdapter controlSam;
  private final List<Command> commands = new ArrayList<Command>();

  LSAsyncTransactionCreatorManagerAdapter(
      String targetSamContext, LSSecuritySetting lsSecuritySetting) {
    this.targetSamContext =
        JsonUtil.getParser().fromJson(targetSamContext, TargetSamContextDto.class);
    this.controlSamReader = ((LSSecuritySettingAdapter) lsSecuritySetting).getControlSamReader();
    this.controlSam = ((LSSecuritySettingAdapter) lsSecuritySetting).getControlSam();
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  public LSAsyncTransactionCreatorManager prepareWriteEventCeiling(
      int eventCeilingNumber, int newValue) {
    Assert.getInstance()
        .isInRange(eventCeilingNumber, 0, 26, "eventCeilingNumber")
        .isInRange(newValue, 0, 0xFFFFFA, "newValue");

    // compute the challenge
    byte[] challenge = new byte[8];
    if (targetSamContext.getSystemKeyTypeToCounterNumberMap() != null) {
      Integer reloadingKeyCounterNumber =
          targetSamContext.getSystemKeyTypeToCounterNumberMap().get(SystemKeyType.RELOADING);
      if (reloadingKeyCounterNumber != null) {
        ByteArrayUtil.copyBytes(
            targetSamContext.getCounterNumberToCounterValueMap().get(reloadingKeyCounterNumber),
            challenge,
            5,
            3);
        // increment counter
        targetSamContext
            .getCounterNumberToCounterValueMap()
            .put(
                reloadingKeyCounterNumber,
                targetSamContext.getCounterNumberToCounterValueMap().get(reloadingKeyCounterNumber)
                    + 1);
      }
    }

    // build the ceiling plain data block
    byte[] plainData = new byte[29];
    plainData[0] = (byte) eventCeilingNumber;
    ByteArrayUtil.copyBytes(newValue, plainData, 1, 3);

    // prepare APDUs
    prepareSelectDiversifier();
    prepareGiveRandom(challenge);
    commands.add(
        new CommandSamDataCipher(
            controlSam, 0, CommandSamDataCipher.DataType.ONE_CEILING_VALUE, plainData));
    return this;
  }

  /** Prepares a "SelectDiversifier" command using the current key diversifier. */
  private void prepareSelectDiversifier() {
    commands.add(new CommandSelectDiversifier(controlSam, targetSamContext.getSerialNumber()));
  }

  /** Prepares a "Give Random" SAM command. */
  private void prepareGiveRandom(byte[] cardChallenge) {
    commands.add(new CmdSamGiveRandom(controlSam, cardChallenge));
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  public LSAsyncTransactionCreatorManager prepareWriteEventCeilings(
      Map<Integer, Integer> eventCeilingNumberToNewValueMap) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  public String exportCommands() {
    SamCommandsDto samCommandsDto = new SamCommandsDto();
    processCommands(commands);
    for (Command command : commands) {
      if (command.getCommandRef() == CommandRef.SAM_DATA_CIPHER) {
        samCommandsDto.add(((CommandSamDataCipher) command).getWriteCommandApduRequest());
      }
    }
    return JsonUtil.toJson(samCommandsDto);
  }

  /**
   * Processes the list of commands provided in argument as expected by {@link #processCommands()}.
   *
   * <p>Note: the list is cleared in all cases.
   *
   * @since 0.3.0
   */
  private void processCommands(List<Command> commands) {
    if (commands.isEmpty()) {
      return;
    }
    // Get the list of C-APDU to transmit
    List<ApduRequestSpi> apduRequests = getApduRequests(commands);

    // Wrap the list of C-APDUs into a card request
    CardRequestSpi cardRequest = new CardRequestAdapter(apduRequests, true);

    // Transmit the commands to the SAM
    CardResponseApi cardResponse = transmitCardRequest(cardRequest);

    // Retrieve the list of R-APDUs
    List<ApduResponseApi> apduResponses = cardResponse.getApduResponses();

    // If there are more responses than requests, then we are unable to fill the card image. In
    // this case we stop processing immediately because it may be a case of fraud, and we throw an
    // exception.
    if (apduResponses.size() > apduRequests.size()) {
      throw new InconsistentDataException(
          MSG_SAM_INCONSISTENT_DATA
              + apduRequests.size()
              + MSG_SAM_NB_RESPONSES
              + apduResponses.size());
    }

    // We go through all the responses (and not the requests) because there may be fewer in the
    // case of an error that occurred in strict mode. In this case the last response will raise an
    // exception.
    for (int i = 0; i < apduResponses.size(); i++) {
      try {
        commands.get(i).parseApduResponse(apduResponses.get(i));
      } catch (CommandException e) {
        CommandRef commandRef = commands.get(i).getCommandRef();
        /*
                  if ((commandRef == CommandRef.PSO_VERIFY_SIGNATURE
                          || commandRef == CommandRef.DATA_CIPHER)
                      && e instanceof SecurityDataException) {
                    throw new InvalidSignatureException("Invalid signature.", e);
                  }
        */
        String sw =
            commands.get(i).getApduResponse() != null
                ? HexUtil.toHex(commands.get(i).getApduResponse().getStatusWord())
                : "null";
        throw new UnexpectedCommandStatusException(
            MSG_SAM_COMMAND_ERROR
                + "while processing responses to SAM commands: "
                + commandRef
                + " ["
                + sw
                + "]",
            e);
      }
    }

    // Finally, if no error has occurred and there are fewer responses than requests, then we
    // throw an exception.
    if (apduResponses.size() < apduRequests.size()) {
      throw new InconsistentDataException(
          MSG_SAM_INCONSISTENT_DATA
              + apduRequests.size()
              + MSG_SAM_NB_RESPONSES
              + apduResponses.size());
    }
  }

  /**
   * Creates a list of {@link ApduRequestSpi} from a list of {@link Command}.
   *
   * @param commands The list of commands.
   * @return An empty list if there is no command.
   * @since 0.1.0
   */
  private List<ApduRequestSpi> getApduRequests(List<Command> commands) {
    List<ApduRequestSpi> apduRequests = new ArrayList<ApduRequestSpi>();
    if (commands != null) {
      for (Command command : commands) {
        apduRequests.add(command.getApduRequest());
      }
    }
    return apduRequests;
  }

  /**
   * Transmits a card request, processes and converts any exceptions.
   *
   * @param cardRequest The card request to transmit.
   * @return The card response.
   */
  private CardResponseApi transmitCardRequest(CardRequestSpi cardRequest) {
    CardResponseApi cardResponse;
    try {
      cardResponse = controlSamReader.transmitCardRequest(cardRequest, ChannelControl.KEEP_OPEN);
    } catch (ReaderBrokenCommunicationException e) {
      throw new ReaderIOException(
          MSG_SAM_READER_COMMUNICATION_ERROR + MSG_WHILE_TRANSMITTING_COMMANDS, e);
    } catch (CardBrokenCommunicationException e) {
      throw new SamIOException(MSG_SAM_COMMUNICATION_ERROR + MSG_WHILE_TRANSMITTING_COMMANDS, e);
    } catch (UnexpectedStatusWordException e) {
      if (logger.isDebugEnabled()) {
        logger.debug("A SAM command has failed: {}", e.getMessage());
      }
      cardResponse = e.getCardResponse();
    }
    return cardResponse;
  }

  @Override
  public LSAsyncTransactionCreatorManager processCommands() {
    throw new IllegalStateException(
        "processCommands() is not allowed during the creation of an asynchronous transaction. Use exportCommands().");
  }
}
