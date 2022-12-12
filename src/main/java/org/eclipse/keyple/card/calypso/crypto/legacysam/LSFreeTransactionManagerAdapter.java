/* **************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/
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
import java.util.Arrays;
import java.util.List;
import org.calypsonet.terminal.calypso.crypto.legacysam.transaction.CommonSignatureComputationData;
import org.calypsonet.terminal.calypso.crypto.legacysam.transaction.CommonSignatureVerificationData;
import org.calypsonet.terminal.calypso.crypto.legacysam.transaction.InconsistentDataException;
import org.calypsonet.terminal.calypso.crypto.legacysam.transaction.InvalidSignatureException;
import org.calypsonet.terminal.calypso.crypto.legacysam.transaction.LSFreeTransactionManager;
import org.calypsonet.terminal.calypso.crypto.legacysam.transaction.ReaderIOException;
import org.calypsonet.terminal.calypso.crypto.legacysam.transaction.SamIOException;
import org.calypsonet.terminal.calypso.crypto.legacysam.transaction.SamRevokedException;
import org.calypsonet.terminal.calypso.crypto.legacysam.transaction.UnexpectedCommandStatusException;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.calypsonet.terminal.card.CardBrokenCommunicationException;
import org.calypsonet.terminal.card.CardResponseApi;
import org.calypsonet.terminal.card.ChannelControl;
import org.calypsonet.terminal.card.ProxyReaderApi;
import org.calypsonet.terminal.card.ReaderBrokenCommunicationException;
import org.calypsonet.terminal.card.UnexpectedStatusWordException;
import org.calypsonet.terminal.card.spi.ApduRequestSpi;
import org.calypsonet.terminal.card.spi.CardRequestSpi;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.core.util.HexUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapter of {@link LSFreeTransactionManager}.
 *
 * @since 0.1.0
 */
class LSFreeTransactionManagerAdapter implements LSFreeTransactionManager {

  private static final Logger logger =
      LoggerFactory.getLogger(LSFreeTransactionManagerAdapter.class);

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
  private static final String MSG_INPUT_OUTPUT_DATA = "input/output data";
  private static final String MSG_SIGNATURE_SIZE = "signature size";
  private static final String MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8 =
      "key diversifier size is in range [1..8]";

  /* Constants */
  private static final int MIN_EVENT_COUNTER_NUMBER = 0;
  private static final int MAX_EVENT_COUNTER_NUMBER = 26;
  private static final int MIN_EVENT_CEILING_NUMBER = 0;
  private static final int MAX_EVENT_CEILING_NUMBER = 26;
  private static final int FIRST_COUNTER_REC1 = 0;
  private static final int LAST_COUNTER_REC1 = 8;
  private static final int FIRST_COUNTER_REC2 = 9;
  private static final int LAST_COUNTER_REC2 = 17;
  private static final int FIRST_COUNTER_REC3 = 18;
  private static final int LAST_COUNTER_REC3 = 26;

  /* Final fields */
  private final ProxyReaderApi samReader;
  private final LegacySamAdapter sam;
  private final byte[] samKeyDiversifier;
  private final List<Command> commands = new ArrayList<Command>();

  /* Dynamic fields */
  private byte[] currentKeyDiversifier;

  LSFreeTransactionManagerAdapter(ProxyReaderApi samReader, LegacySamAdapter sam) {
    this.samReader = samReader;
    this.sam = sam;
    this.samKeyDiversifier = sam.getSerialNumber();
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public LSFreeTransactionManager prepareComputeSignature(CommonSignatureComputationData<?> data) {

    if (data instanceof BasicSignatureComputationDataAdapter) {
      // Basic signature
      BasicSignatureComputationDataAdapter dataAdapter =
          (BasicSignatureComputationDataAdapter) data;

      Assert.getInstance()
          .notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
          .notNull(dataAdapter.getData(), "data to sign")
          .isInRange(dataAdapter.getData().length, 1, 208, "length of data to sign")
          .isTrue(
              dataAdapter.getData().length % 8 == 0, "length of data to sign is a multiple of 8")
          .isInRange(dataAdapter.getSignatureSize(), 1, 8, MSG_SIGNATURE_SIZE)
          .isTrue(
              dataAdapter.getKeyDiversifier() == null
                  || (dataAdapter.getKeyDiversifier().length >= 1
                      && dataAdapter.getKeyDiversifier().length <= 8),
              MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

      prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
      commands.add(new CommandDataCipher(sam, dataAdapter, null));

    } else if (data instanceof TraceableSignatureComputationDataAdapter) {
      // Traceable signature
      TraceableSignatureComputationDataAdapter dataAdapter =
          (TraceableSignatureComputationDataAdapter) data;

      Assert.getInstance()
          .notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
          .notNull(dataAdapter.getData(), "data to sign")
          .isInRange(
              dataAdapter.getData().length,
              1,
              dataAdapter.isSamTraceabilityMode() ? 206 : 208,
              "length of data to sign")
          .isInRange(dataAdapter.getSignatureSize(), 1, 8, MSG_SIGNATURE_SIZE)
          .isTrue(
              !dataAdapter.isSamTraceabilityMode()
                  || (dataAdapter.getTraceabilityOffset() >= 0
                      && dataAdapter.getTraceabilityOffset()
                          <= ((dataAdapter.getData().length * 8)
                              - (dataAdapter.isPartialSamSerialNumber() ? 7 * 8 : 8 * 8))),
              "traceability offset is in range [0.."
                  + ((dataAdapter.getData().length * 8)
                      - (dataAdapter.isPartialSamSerialNumber() ? 7 * 8 : 8 * 8))
                  + "]")
          .isTrue(
              dataAdapter.getKeyDiversifier() == null
                  || (dataAdapter.getKeyDiversifier().length >= 1
                      && dataAdapter.getKeyDiversifier().length <= 8),
              MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

      prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
      commands.add(new CommandPsoComputeSignature(sam, dataAdapter));

    } else {
      throw new IllegalArgumentException(
          "The provided data must be an instance of 'BasicSignatureComputationDataAdapter' or 'TraceableSignatureComputationDataAdapter'");
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public LSFreeTransactionManager prepareVerifySignature(CommonSignatureVerificationData<?> data) {
    if (data instanceof BasicSignatureVerificationDataAdapter) {
      // Basic signature
      BasicSignatureVerificationDataAdapter dataAdapter =
          (BasicSignatureVerificationDataAdapter) data;

      Assert.getInstance()
          .notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
          .notNull(dataAdapter.getData(), "signed data to verify")
          .isInRange(dataAdapter.getData().length, 1, 208, "length of signed data to verify")
          .isTrue(
              dataAdapter.getData().length % 8 == 0, "length of data to verify is a multiple of 8")
          .notNull(dataAdapter.getSignature(), "signature")
          .isInRange(dataAdapter.getSignature().length, 1, 8, MSG_SIGNATURE_SIZE)
          .isTrue(
              dataAdapter.getKeyDiversifier() == null
                  || (dataAdapter.getKeyDiversifier().length >= 1
                      && dataAdapter.getKeyDiversifier().length <= 8),
              MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

      prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
      commands.add(new CommandDataCipher(sam, null, dataAdapter));

    } else if (data instanceof TraceableSignatureVerificationDataAdapter) {
      // Traceable signature
      TraceableSignatureVerificationDataAdapter dataAdapter =
          (TraceableSignatureVerificationDataAdapter) data;

      Assert.getInstance()
          .notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
          .notNull(dataAdapter.getData(), "signed data to verify")
          .isInRange(
              dataAdapter.getData().length,
              1,
              dataAdapter.isSamTraceabilityMode() ? 206 : 208,
              "length of signed data to verify")
          .notNull(dataAdapter.getSignature(), "signature")
          .isInRange(dataAdapter.getSignature().length, 1, 8, MSG_SIGNATURE_SIZE)
          .isTrue(
              !dataAdapter.isSamTraceabilityMode()
                  || (dataAdapter.getTraceabilityOffset() >= 0
                      && dataAdapter.getTraceabilityOffset()
                          <= ((dataAdapter.getData().length * 8)
                              - (dataAdapter.isPartialSamSerialNumber() ? 7 * 8 : 8 * 8))),
              "traceability offset is in range [0.."
                  + ((dataAdapter.getData().length * 8)
                      - (dataAdapter.isPartialSamSerialNumber() ? 7 * 8 : 8 * 8))
                  + "]")
          .isTrue(
              dataAdapter.getKeyDiversifier() == null
                  || (dataAdapter.getKeyDiversifier().length >= 1
                      && dataAdapter.getKeyDiversifier().length <= 8),
              MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

      // Check SAM revocation status if requested.
      if (dataAdapter.getSamRevocationService() != null) {
        // Extract the SAM serial number and the counter value from the data.
        byte[] samSerialNumber =
            ByteArrayUtil.extractBytes(
                dataAdapter.getData(),
                dataAdapter.getTraceabilityOffset(),
                dataAdapter.isPartialSamSerialNumber() ? 3 : 4);

        int samCounterValue =
            ByteArrayUtil.extractInt(
                ByteArrayUtil.extractBytes(
                    dataAdapter.getData(),
                    dataAdapter.getTraceabilityOffset()
                        + (dataAdapter.isPartialSamSerialNumber() ? 3 * 8 : 4 * 8),
                    3),
                0,
                3,
                false);

        // Is SAM revoked ?
        if (dataAdapter.getSamRevocationService().isSamRevoked(samSerialNumber, samCounterValue)) {
          throw new SamRevokedException(
              String.format(
                  "SAM with serial number '%s' and counter value '%d' is revoked.",
                  HexUtil.toHex(samSerialNumber), samCounterValue));
        }
      }

      prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
      commands.add(new CommandPsoVerifySignature(sam, dataAdapter));

    } else {
      throw new IllegalArgumentException(
          "The provided data must be an instance of 'CommonSignatureVerificationDataAdapter'");
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public LSFreeTransactionManager prepareReadEventCounter(int eventCounterNumber) {

    Assert.getInstance()
        .isInRange(
            eventCounterNumber,
            MIN_EVENT_COUNTER_NUMBER,
            MAX_EVENT_COUNTER_NUMBER,
            "eventCounterNumber");

    commands.add(
        new CommandReadEventCounter(
            sam,
            CommandReadEventCounter.CounterOperationType.READ_SINGLE_COUNTER,
            eventCounterNumber));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public LSFreeTransactionManager prepareReadEventCounters(
      int fromEventCounterNumber, int toEventCounterNumber) {

    Assert.getInstance()
        .isInRange(
            fromEventCounterNumber,
            MIN_EVENT_COUNTER_NUMBER,
            MAX_EVENT_COUNTER_NUMBER,
            "fromEventCounterNumber")
        .isInRange(
            toEventCounterNumber,
            MIN_EVENT_COUNTER_NUMBER,
            MAX_EVENT_COUNTER_NUMBER,
            "toEventCounterNumber")
        .greaterOrEqual(
            toEventCounterNumber,
            fromEventCounterNumber,
            "fromEventCounterNumber/toEventCounterNumber");

    if (areIntervalsOverlapping(
        FIRST_COUNTER_REC1, LAST_COUNTER_REC1, fromEventCounterNumber, toEventCounterNumber)) {
      commands.add(
          new CommandReadEventCounter(
              sam, CommandReadEventCounter.CounterOperationType.READ_COUNTER_RECORD, 1));
    }
    if (areIntervalsOverlapping(
        FIRST_COUNTER_REC2, LAST_COUNTER_REC2, fromEventCounterNumber, toEventCounterNumber)) {
      commands.add(
          new CommandReadEventCounter(
              sam, CommandReadEventCounter.CounterOperationType.READ_COUNTER_RECORD, 2));
    }
    if (areIntervalsOverlapping(
        FIRST_COUNTER_REC3, LAST_COUNTER_REC3, fromEventCounterNumber, toEventCounterNumber)) {
      commands.add(
          new CommandReadEventCounter(
              sam, CommandReadEventCounter.CounterOperationType.READ_COUNTER_RECORD, 3));
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public LSFreeTransactionManager prepareReadEventCeiling(int eventCeilingNumber) {

    Assert.getInstance()
        .isInRange(
            eventCeilingNumber,
            MIN_EVENT_CEILING_NUMBER,
            MAX_EVENT_CEILING_NUMBER,
            "eventCeilingNumber");

    commands.add(
        new CommandReadCeilings(
            sam,
            CommandReadCeilings.CeilingsOperationType.READ_SINGLE_CEILING,
            eventCeilingNumber));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public LSFreeTransactionManager prepareReadEventCeilings(
      int fromEventCeilingNumber, int toEventCeilingNumber) {

    Assert.getInstance()
        .isInRange(
            fromEventCeilingNumber,
            MIN_EVENT_CEILING_NUMBER,
            MAX_EVENT_CEILING_NUMBER,
            "fromEventCeilingNumber")
        .isInRange(
            toEventCeilingNumber,
            MIN_EVENT_CEILING_NUMBER,
            MAX_EVENT_CEILING_NUMBER,
            "toEventCeilingNumber")
        .greaterOrEqual(
            toEventCeilingNumber,
            fromEventCeilingNumber,
            "fromEventCeilingNumber/toEventCeilingNumber");

    if (areIntervalsOverlapping(
        FIRST_COUNTER_REC1, LAST_COUNTER_REC1, fromEventCeilingNumber, toEventCeilingNumber)) {
      commands.add(
          new CommandReadCeilings(
              sam, CommandReadCeilings.CeilingsOperationType.READ_CEILING_RECORD, 1));
    }
    if (areIntervalsOverlapping(
        FIRST_COUNTER_REC2, LAST_COUNTER_REC2, fromEventCeilingNumber, toEventCeilingNumber)) {
      commands.add(
          new CommandReadCeilings(
              sam, CommandReadCeilings.CeilingsOperationType.READ_CEILING_RECORD, 2));
    }
    if (areIntervalsOverlapping(
        FIRST_COUNTER_REC3, LAST_COUNTER_REC3, fromEventCeilingNumber, toEventCeilingNumber)) {
      commands.add(
          new CommandReadCeilings(
              sam, CommandReadCeilings.CeilingsOperationType.READ_CEILING_RECORD, 3));
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public LSFreeTransactionManager processCommands() {
    if (commands.isEmpty()) {
      return this;
    }
    try {
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
          if ((commandRef == CommandRef.PSO_VERIFY_SIGNATURE
                  || commandRef == CommandRef.DATA_CIPHER)
              && e instanceof SecurityDataException) {
            throw new InvalidSignatureException("Invalid signature.", e);
          }
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
    } finally {
      // Reset the list of commands.
      commands.clear();
    }
    return this;
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
      cardResponse = samReader.transmitCardRequest(cardRequest, ChannelControl.KEEP_OPEN);
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

  /**
   * Prepares a "SelectDiversifier" command using a specific or the default key diversifier if it is
   * not already selected.
   *
   * @param specificKeyDiversifier The specific key diversifier (optional).
   * @since 0.1.0
   */
  private void prepareSelectDiversifierIfNeeded(byte[] specificKeyDiversifier) {
    if (specificKeyDiversifier != null) {
      if (!Arrays.equals(specificKeyDiversifier, currentKeyDiversifier)) {
        currentKeyDiversifier = specificKeyDiversifier;
        prepareSelectDiversifier();
      }
    } else {
      prepareSelectDiversifierIfNeeded();
    }
  }

  /**
   * Prepares a "SelectDiversifier" command using the default key diversifier if it is not already
   * selected.
   *
   * @since 0.1.0
   */
  private void prepareSelectDiversifierIfNeeded() {
    if (!Arrays.equals(currentKeyDiversifier, samKeyDiversifier)) {
      currentKeyDiversifier = samKeyDiversifier;
      prepareSelectDiversifier();
    }
  }

  /** Prepares a "SelectDiversifier" command using the current key diversifier. */
  private void prepareSelectDiversifier() {
    commands.add(new CommandSelectDiversifier(sam, currentKeyDiversifier));
  }

  /**
   * Overlapping interval test
   *
   * @param startA beginning of the A interval.
   * @param endA end of the A interval.
   * @param startB beginning of the B interval.
   * @param endB end of the B interval.
   * @return true if the intervals A and B overlap.
   */
  private boolean areIntervalsOverlapping(int startA, int endA, int startB, int endB) {
    return startA <= endB && endA >= startB;
  }
}
