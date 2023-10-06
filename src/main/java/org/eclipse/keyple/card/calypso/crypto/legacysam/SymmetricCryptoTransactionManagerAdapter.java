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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keyple.core.util.json.JsonUtil;
import org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySam;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.*;
import org.eclipse.keypop.calypso.crypto.symmetric.SvCommandSecurityDataApi;
import org.eclipse.keypop.calypso.crypto.symmetric.SymmetricCryptoException;
import org.eclipse.keypop.calypso.crypto.symmetric.SymmetricCryptoIOException;
import org.eclipse.keypop.calypso.crypto.symmetric.spi.*;
import org.eclipse.keypop.card.*;
import org.eclipse.keypop.card.spi.ApduRequestSpi;
import org.eclipse.keypop.card.spi.CardRequestSpi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapter of {@link SymmetricCryptoTransactionManagerSpi} and {@link
 * CardTransactionLegacySamExtension}.
 *
 * @since 2.3.1
 */
final class SymmetricCryptoTransactionManagerAdapter
    implements SymmetricCryptoTransactionManagerSpi, CardTransactionLegacySamExtension {

  private static final Logger logger =
      LoggerFactory.getLogger(SymmetricCryptoTransactionManagerAdapter.class);

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

  /* Final fields */
  private final ProxyReaderApi samReader;
  private final LegacySamAdapter sam;
  private final byte[] cardKeyDiversifier;
  private final boolean isExtendedModeRequired;
  private final int maxCardApduLengthSupported;
  private final List<byte[]> transactionAuditData;
  private final List<Command> samCommands = new ArrayList<Command>();

  /* Dynamic fields */
  private byte[] currentKeyDiversifier;
  private DigestManager digestManager;
  private boolean isEncryptionActive;
  private boolean isSelectDiversifierNeededOnDigestInit;

  /**
   * Creates an instance of {@link CardTransactionLegacySamExtension}.
   *
   * @param samReader The reader through which the SAM communicates.
   * @param sam The initial SAM data provided by the selection process.
   * @param cardKeyDiversifier The diversifier to use for card related computations.
   * @param useExtendedMode True if the extended mode should be used.
   * @param maxCardApduLengthSupported The maximum length, in bytes, that a single APDU command sent
   *     to the SAM can contain.
   * @since 2.0.0
   */
  SymmetricCryptoTransactionManagerAdapter(
      ProxyReaderApi samReader,
      LegacySamAdapter sam,
      byte[] cardKeyDiversifier,
      boolean useExtendedMode,
      int maxCardApduLengthSupported,
      List<byte[]> transactionAuditData) {
    this.samReader = samReader;
    this.sam = sam;
    this.cardKeyDiversifier = cardKeyDiversifier;
    isExtendedModeRequired = useExtendedMode;
    this.maxCardApduLengthSupported = maxCardApduLengthSupported;
    this.transactionAuditData = transactionAuditData;
  }

  /**
   * Gets the command context.
   *
   * @return An instance of {@link DtoAdapters.CommandContextDto}.
   * @since 0.3.0
   */
  DtoAdapters.CommandContextDto getContext() {
    return new DtoAdapters.CommandContextDto(sam, null, null);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.4
   */
  @Override
  public void preInitTerminalSecureSessionContext()
      throws SymmetricCryptoException, SymmetricCryptoIOException {
    CommandGetChallenge cmd = new CommandGetChallenge(getContext(), isExtendedModeRequired ? 8 : 4);
    samCommands.add(cmd);
    processCommands();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public byte[] initTerminalSecureSessionContext()
      throws SymmetricCryptoIOException, SymmetricCryptoException {
    if (isSelectDiversifierNeeded(cardKeyDiversifier)) {
      isSelectDiversifierNeededOnDigestInit = true;
    }
    byte[] challenge = sam.popChallenge();
    if (challenge == null) {
      preInitTerminalSecureSessionContext();
      challenge = sam.popChallenge();
    }
    return challenge;
  }

  /**
   * @param keyDiversifier The key diversifier to use.
   * @return true if the current key diversifier has changed and therefore a "Select Diversifier"
   *     command is needed.
   */
  private boolean isSelectDiversifierNeeded(byte[] keyDiversifier) {
    if (!Arrays.equals(currentKeyDiversifier, keyDiversifier)) {
      currentKeyDiversifier = keyDiversifier;
      return true;
    }
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public void initTerminalSessionMac(byte[] openSecureSessionDataOut, byte kif, byte kvc) {
    digestManager = new DigestManager(openSecureSessionDataOut, kif, kvc);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public byte[] updateTerminalSessionMac(byte[] cardApdu)
      throws SymmetricCryptoIOException, SymmetricCryptoException {
    if (isEncryptionActive) {
      // Encrypted mode.
      // We first prepare any pending plain-text commands in order to optimize the possible
      // groupings.
      digestManager.prepareCommands();
      // We then prepare the command for encryption.
      CommandDigestUpdate samCommand = digestManager.prepareCommandForEncryption(cardApdu);
      // Process commands.
      processCommands();
      // Return the encrypted/decrypted value.
      return samCommand.getProcessedData();
    } else {
      // Plain mode.
      digestManager.updateSession(cardApdu);
      return null; // NOSONAR
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public byte[] finalizeTerminalSessionMac()
      throws SymmetricCryptoIOException, SymmetricCryptoException {
    digestManager.prepareAllCommands();
    digestManager = null;
    CommandDigestClose cmdSamDigestClose =
        (CommandDigestClose) samCommands.get(samCommands.size() - 1);
    processCommands();
    return cmdSamDigestClose.getMac();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public byte[] generateTerminalSessionMac()
      throws SymmetricCryptoIOException, SymmetricCryptoException {
    // We first prepare any pending commands in order to optimize the possible groupings.
    digestManager.prepareCommands();
    // Then we prepare the "Digest Internal Authenticate" command.
    CommandDigestInternalAuthenticate cmdSamDigestInternalAuthenticate =
        new CommandDigestInternalAuthenticate(getContext());
    samCommands.add(cmdSamDigestInternalAuthenticate);
    // Process commands.
    processCommands();
    // Return the terminal session MAC.
    return cmdSamDigestInternalAuthenticate.getTerminalSignature();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public void activateEncryption() {
    isEncryptionActive = true;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public void deactivateEncryption() {
    isEncryptionActive = false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public boolean isCardSessionMacValid(byte[] cardSessionMac)
      throws SymmetricCryptoIOException, SymmetricCryptoException {
    samCommands.add(new CommandDigestAuthenticate(getContext(), cardSessionMac));
    try {
      processCommands();
      return true;
    } catch (InvalidCardMacException e) {
      return false;
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public void computeSvCommandSecurityData(SvCommandSecurityDataApi svCommandSecurityData)
      throws SymmetricCryptoIOException, SymmetricCryptoException {
    prepareSelectDiversifierIfNeeded();
    if (svCommandSecurityData.getSvCommandPartialRequest()[0] == (byte) 0xB8) {
      samCommands.add(new CommandSvPrepareLoad(getContext(), svCommandSecurityData));
    } else {
      samCommands.add(new CommandSvPrepareDebitOrUndebit(getContext(), svCommandSecurityData));
    }
    processCommands();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public boolean isCardSvMacValid(byte[] cardSvMac)
      throws SymmetricCryptoIOException, SymmetricCryptoException {
    samCommands.add(new CommandSvCheck(getContext(), cardSvMac));
    try {
      processCommands();
      return true;
    } catch (InvalidCardMacException e) {
      return false;
    }
  }

  /** Prepares a "Give Random" SAM command. */
  private void prepareGiveRandom(byte[] cardChallenge) {
    prepareSelectDiversifierIfNeeded();
    samCommands.add(new CommandGiveRandom(getContext(), cardChallenge));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public byte[] cipherPinForPresentation(byte[] cardChallenge, byte[] pin, Byte kif, Byte kvc)
      throws SymmetricCryptoIOException, SymmetricCryptoException {
    return cipherPin(cardChallenge, pin, null, kif, kvc);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public byte[] cipherPinForModification(
      byte[] cardChallenge, byte[] currentPin, byte[] newPin, Byte kif, Byte kvc)
      throws SymmetricCryptoIOException, SymmetricCryptoException {
    return cipherPin(cardChallenge, currentPin, newPin, kif, kvc);
  }

  private byte[] cipherPin(
      byte[] cardChallenge, byte[] currentPin, byte[] newPin, Byte kif, Byte kvc)
      throws SymmetricCryptoIOException, SymmetricCryptoException {
    byte pinCipheringKif;
    byte pinCipheringKvc;
    if (digestManager != null && digestManager.sessionKif != 0) {
      // the current work key has been set (a secure session is open)
      pinCipheringKif = digestManager.sessionKif;
      pinCipheringKvc = digestManager.sessionKvc;
    } else {
      // no current work key is available (outside secure session)
      if (kif == null || kvc == null) {
        String msg = newPin == null ? "verification" : "modification";
        throw new IllegalStateException(
            String.format("No KIF or KVC defined for the PIN %s ciphering key", msg));
      }
      pinCipheringKif = kif;
      pinCipheringKvc = kvc;
    }
    prepareGiveRandom(cardChallenge);
    CommandCardCipherPin cmd =
        new CommandCardCipherPin(
            getContext(), pinCipheringKif, pinCipheringKvc, currentPin, newPin);
    samCommands.add(cmd);
    processCommands();
    return cmd.getCipheredData();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public byte[] generateCipheredCardKey(
      byte[] cardChallenge,
      byte issuerKeyKif,
      byte issuerKeyKvc,
      byte targetKeyKif,
      byte targetKeyKvc)
      throws SymmetricCryptoIOException, SymmetricCryptoException {
    prepareGiveRandom(cardChallenge);
    CommandCardGenerateKey cmd =
        new CommandCardGenerateKey(
            getContext(), issuerKeyKif, issuerKeyKvc, targetKeyKif, targetKeyKvc);
    samCommands.add(cmd);
    processCommands();
    return cmd.getCipheredData();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public void synchronize() throws SymmetricCryptoIOException, SymmetricCryptoException {
    processCommands();
  }

  private void processCommands() throws SymmetricCryptoException, SymmetricCryptoIOException {
    // If there are pending SAM commands and the secure session is open and the "Digest Init"
    // command is not already executed, then we need to flush the session pending commands by
    // executing the pending "digest" commands "BEFORE" the other SAM commands to make sure that
    // between the session "Get Challenge" and the "Digest Init", there is no other command
    // inserted.
    if (!samCommands.isEmpty() && digestManager != null && !digestManager.isDigestInitDone) {
      digestManager.prepareDigestInit();
    }
    if (samCommands.isEmpty()) {
      return;
    }
    try {
      // Get the list of C-APDU to transmit
      List<ApduRequestSpi> apduRequests = getApduRequests(samCommands);

      // Wrap the list of C-APDUs into a card request
      CardRequestSpi cardRequest = new DtoAdapters.CardRequestAdapter(apduRequests, true);

      // Transmit the commands to the SAM
      CardResponseApi cardResponse = transmitCardRequest(cardRequest);

      // Retrieve the list of R-APDUs
      List<ApduResponseApi> apduResponses =
          cardResponse.getApduResponses(); // NOSONAR cannot be null

      // If there are more responses than requests, then we are unable to fill the card image. In
      // this case we stop processing immediately because it may be a case of fraud, and we throw an
      // exception.
      if (apduResponses.size() > apduRequests.size()) {
        throw new SymmetricCryptoException(
            MSG_SAM_INCONSISTENT_DATA
                + apduRequests.size()
                + MSG_SAM_NB_RESPONSES
                + apduResponses.size(),
            new InconsistentDataException(
                MSG_SAM_INCONSISTENT_DATA
                    + apduRequests.size()
                    + MSG_SAM_NB_RESPONSES
                    + apduResponses.size()
                    + getTransactionAuditDataAsString()));
      }

      // We go through all the responses (and not the requests) because there may be fewer in the
      // case of an error that occurred in strict mode. In this case the last response will raise an
      // exception.
      for (int i = 0; i < apduResponses.size(); i++) {
        try {
          samCommands.get(i).parseResponse(apduResponses.get(i));
        } catch (CommandException e) {
          CommandRef commandRef = samCommands.get(i).getCommandRef();
          if (commandRef == CommandRef.DIGEST_AUTHENTICATE && e instanceof SecurityDataException) {
            throw new InvalidCardMacException("Invalid card signature.");
          } else if ((commandRef == CommandRef.PSO_VERIFY_SIGNATURE
                  || commandRef == CommandRef.DATA_CIPHER)
              && e instanceof SecurityDataException) {
            throw new InvalidSignatureException("Invalid signature.", e);
          } else if (commandRef == CommandRef.SV_CHECK && e instanceof SecurityDataException) {
            throw new InvalidCardMacException("Invalid SV card signature.");
          }
          String sw =
              samCommands.get(i).getApduResponse() != null
                  ? HexUtil.toHex(samCommands.get(i).getApduResponse().getStatusWord())
                  : "null";
          throw new SymmetricCryptoException(
              MSG_SAM_COMMAND_ERROR
                  + "while processing responses to SAM commands: "
                  + commandRef
                  + " ["
                  + sw
                  + "]",
              new UnexpectedCommandStatusException(
                  MSG_SAM_COMMAND_ERROR
                      + "while processing responses to SAM commands: "
                      + commandRef
                      + " ["
                      + sw
                      + "]"
                      + getTransactionAuditDataAsString(),
                  e));
        }
      }

      // Finally, if no error has occurred and there are fewer responses than requests, then we
      // throw an exception.
      if (apduResponses.size() < apduRequests.size()) {
        throw new SymmetricCryptoException(
            MSG_SAM_INCONSISTENT_DATA
                + apduRequests.size()
                + MSG_SAM_NB_RESPONSES
                + apduResponses.size(),
            new InconsistentDataException(
                MSG_SAM_INCONSISTENT_DATA
                    + apduRequests.size()
                    + MSG_SAM_NB_RESPONSES
                    + apduResponses.size()
                    + getTransactionAuditDataAsString()));
      }
    } finally {
      // Reset the list of commands.
      samCommands.clear();
    }
  }

  /**
   * Creates a list of {@link ApduRequestSpi} from a list of {@link Command}.
   *
   * @param commands The list of commands.
   * @return An empty list if there is no command.
   */
  private static List<ApduRequestSpi> getApduRequests(List<Command> commands) {
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
  private CardResponseApi transmitCardRequest(CardRequestSpi cardRequest)
      throws SymmetricCryptoIOException {
    CardResponseApi cardResponse;
    try {
      cardResponse = samReader.transmitCardRequest(cardRequest, ChannelControl.KEEP_OPEN);
    } catch (ReaderBrokenCommunicationException e) {
      saveTransactionAuditData(cardRequest, e.getCardResponse());
      throw new SymmetricCryptoIOException(
          MSG_SAM_READER_COMMUNICATION_ERROR + MSG_WHILE_TRANSMITTING_COMMANDS,
          new ReaderIOException(
              MSG_SAM_READER_COMMUNICATION_ERROR
                  + MSG_WHILE_TRANSMITTING_COMMANDS
                  + getTransactionAuditDataAsString(),
              e));
    } catch (CardBrokenCommunicationException e) {
      saveTransactionAuditData(cardRequest, e.getCardResponse());
      throw new SymmetricCryptoIOException(
          MSG_SAM_COMMUNICATION_ERROR + MSG_WHILE_TRANSMITTING_COMMANDS,
          new SamIOException(
              MSG_SAM_COMMUNICATION_ERROR
                  + MSG_WHILE_TRANSMITTING_COMMANDS
                  + getTransactionAuditDataAsString(),
              e));
    } catch (UnexpectedStatusWordException e) {
      if (logger.isDebugEnabled()) {
        logger.debug("A SAM command has failed: {}", e.getMessage());
      }
      cardResponse = e.getCardResponse();
    }
    saveTransactionAuditData(cardRequest, cardResponse);
    return cardResponse;
  }

  /**
   * Saves the provided exchanged APDU commands in the list of transaction audit data.
   *
   * @param cardRequest The card request.
   * @param cardResponse The associated card response.
   */
  private void saveTransactionAuditData(CardRequestSpi cardRequest, CardResponseApi cardResponse) {
    if (cardResponse != null) {
      List<ApduRequestSpi> requests = cardRequest.getApduRequests();
      List<ApduResponseApi> responses = cardResponse.getApduResponses();
      for (int i = 0; i < responses.size(); i++) {
        transactionAuditData.add(requests.get(i).getApdu());
        transactionAuditData.add(responses.get(i).getApdu());
      }
    }
  }

  /**
   * Returns a string representation of the transaction audit data.
   *
   * @return A not empty string.
   */
  private String getTransactionAuditDataAsString() {
    return "\nTransaction audit JSON data: {"
        + "\"sam\":"
        + sam
        + ",\"apdus\":"
        + JsonUtil.toJson(transactionAuditData)
        + "}";
  }

  /** Prepares a "SelectDiversifier" command using the current key diversifier. */
  private void prepareSelectDiversifier() {
    samCommands.add(new CommandSelectDiversifier(getContext(), currentKeyDiversifier));
  }

  /**
   * Prepares a "SelectDiversifier" command using a specific or the default key diversifier if it is
   * not already selected.
   *
   * @param specificKeyDiversifier The specific key diversifier (optional).
   */
  private void prepareSelectDiversifierIfNeeded(byte[] specificKeyDiversifier) {
    if (specificKeyDiversifier != null) {
      if (isSelectDiversifierNeeded(specificKeyDiversifier)) {
        prepareSelectDiversifier();
      }
    } else {
      prepareSelectDiversifierIfNeeded();
    }
  }

  /**
   * Prepares a "SelectDiversifier" command using the default key diversifier if it is not already
   * selected.
   */
  private void prepareSelectDiversifierIfNeeded() {
    if (isSelectDiversifierNeeded(cardKeyDiversifier)) {
      prepareSelectDiversifier();
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.4.0
   */
  @Override
  public CardTransactionLegacySamExtension prepareComputeSignature(
      SignatureComputationData<?> data) {

    if (data instanceof DtoAdapters.BasicSignatureComputationDataAdapter) {
      // Basic signature
      DtoAdapters.BasicSignatureComputationDataAdapter dataAdapter =
          (DtoAdapters.BasicSignatureComputationDataAdapter) data;

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
      samCommands.add(new CommandDataCipher(getContext(), dataAdapter, null));

    } else if (data instanceof DtoAdapters.TraceableSignatureComputationDataAdapter) {
      // Traceable signature
      DtoAdapters.TraceableSignatureComputationDataAdapter dataAdapter =
          (DtoAdapters.TraceableSignatureComputationDataAdapter) data;

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
                              - (dataAdapter.getSamTraceabilityMode()
                                      == SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER
                                  ? 7 * 8
                                  : 8 * 8))),
              "traceability offset is in range [0.."
                  + ((dataAdapter.getData().length * 8)
                      - (dataAdapter.getSamTraceabilityMode()
                              == SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER
                          ? 7 * 8
                          : 8 * 8))
                  + "]")
          .isTrue(
              dataAdapter.getKeyDiversifier() == null
                  || (dataAdapter.getKeyDiversifier().length >= 1
                      && dataAdapter.getKeyDiversifier().length <= 8),
              MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

      prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
      samCommands.add(new CommandPsoComputeSignature(getContext(), dataAdapter));

    } else {
      throw new IllegalArgumentException(
          "The provided data must be an instance of 'BasicSignatureComputationDataAdapter'"
              + " or 'TraceableSignatureComputationDataAdapter'");
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.4.0
   */
  @Override
  public CardTransactionLegacySamExtension prepareVerifySignature(
      SignatureVerificationData<?> data) {
    if (data instanceof DtoAdapters.BasicSignatureVerificationDataAdapter) {
      // Basic signature
      DtoAdapters.BasicSignatureVerificationDataAdapter dataAdapter =
          (DtoAdapters.BasicSignatureVerificationDataAdapter) data;

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
      samCommands.add(new CommandDataCipher(getContext(), null, dataAdapter));

    } else if (data instanceof DtoAdapters.TraceableSignatureVerificationDataAdapter) {
      // Traceable signature
      DtoAdapters.TraceableSignatureVerificationDataAdapter dataAdapter =
          (DtoAdapters.TraceableSignatureVerificationDataAdapter) data;

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
                              - (dataAdapter.getSamTraceabilityMode()
                                      == SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER
                                  ? 7 * 8
                                  : 8 * 8))),
              "traceability offset is in range [0.."
                  + ((dataAdapter.getData().length * 8)
                      - (dataAdapter.getSamTraceabilityMode()
                              == SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER
                          ? 7 * 8
                          : 8 * 8))
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
                dataAdapter.getSamTraceabilityMode() == SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER
                    ? 3
                    : 4);

        int samCounterValue =
            ByteArrayUtil.extractInt(
                ByteArrayUtil.extractBytes(
                    dataAdapter.getData(),
                    dataAdapter.getTraceabilityOffset()
                        + (dataAdapter.getSamTraceabilityMode()
                                == SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER
                            ? 3 * 8
                            : 4 * 8),
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
      samCommands.add(new CommandPsoVerifySignature(getContext(), dataAdapter));

    } else {
      throw new IllegalArgumentException(
          "The provided data must be an instance of 'CommonSignatureVerificationDataAdapter'");
    }
    return this;
  }

  /** The manager of the digest session. */
  private final class DigestManager {

    private final byte[] openSecureSessionDataOut;
    private final byte sessionKif;
    private final byte sessionKvc;
    private final List<byte[]> cardApdus = new ArrayList<byte[]>();
    private boolean isDigestInitDone;
    boolean isRequest = true;

    /**
     * Creates a new digest manager.
     *
     * @param openSecureSessionDataOut The data out of the "Open Secure Session" card command.
     * @param kif The KIF to use.
     * @param kvc The KVC to use.
     */
    private DigestManager(byte[] openSecureSessionDataOut, byte kif, byte kvc) {
      this.openSecureSessionDataOut = openSecureSessionDataOut;
      sessionKif = kif;
      sessionKvc = kvc;
    }

    /**
     * Add one or more exchanged card APDUs to the buffer.
     *
     * @param cardApdu The APDU.
     */
    private void updateSession(byte[] cardApdu) {
      // If the request is of case4 type, LE must be excluded from the digest computation. In this
      // case, we remove here the last byte of the command buffer.
      // CL-C4-MAC.1
      if (isRequest) {
        cardApdus.add(
            ApduUtil.isCase4(cardApdu)
                ? Arrays.copyOfRange(cardApdu, 0, cardApdu.length - 1)
                : cardApdu);
      } else {
        cardApdus.add(cardApdu);
      }
      isRequest = !isRequest;
    }

    /**
     * Prepares a digest update command for encryption mode.
     *
     * @param cardApdu The card APDU.
     */
    private CommandDigestUpdate prepareCommandForEncryption(byte[] cardApdu) {
      updateSession(cardApdu);
      // Prepare the "Digest Update" commands and flush the buffer.
      CommandDigestUpdate command =
          new CommandDigestUpdate(getContext(), true, cardApdus.remove(0));
      samCommands.add(command);
      return command;
    }

    /** Prepares all intermediate digest commands. */
    private void prepareCommands() {
      // Prepare the "Digest Init" command if not already done.
      if (!isDigestInitDone) {
        prepareDigestInit();
      }
      // Prepare the "Digest Update" commands and flush the buffer.
      prepareDigestUpdate();
      cardApdus.clear();
    }

    /** Prepares all pending digest commands. */
    private void prepareAllCommands() {
      prepareCommands();
      // Prepare the "Digest Close" command.
      prepareDigestClose();
    }

    /** Prepares the "Digest Init" SAM command. */
    private void prepareDigestInit() {
      int index = 0;
      if (isSelectDiversifierNeededOnDigestInit) {
        samCommands.add(index++, new CommandSelectDiversifier(getContext(), cardKeyDiversifier));
      }
      // CL-SAM-DINIT.1
      samCommands.add(
          index,
          new CommandDigestInit(
              getContext(),
              false,
              isExtendedModeRequired,
              sessionKif,
              sessionKvc,
              openSecureSessionDataOut));
      isDigestInitDone = true;
    }

    /** Prepares the "Digest Update" SAM command. */
    private void prepareDigestUpdate() {
      if (cardApdus.isEmpty()) {
        return;
      }
      // CL-SAM-DUPDATE.1
      if (sam.getProductType() == LegacySam.ProductType.SAM_C1) {
        // Digest Update Multiple
        byte[] buffer = new byte[255];
        int i = 0;
        for (byte[] cardApdu : cardApdus) {
          if (i + cardApdu.length + 1 > maxCardApduLengthSupported) {
            // Add command and reset buffer
            if (i != 0) {
              samCommands.add(
                  new CommandDigestUpdateMultiple(getContext(), Arrays.copyOf(buffer, i)));
            }
            i = 0;
          }
          if (cardApdu.length != maxCardApduLengthSupported) {
            // Add [length][apdu] to current buffer
            buffer[i++] = (byte) cardApdu.length;
            System.arraycopy(cardApdu, 0, buffer, i, cardApdu.length);
            i += cardApdu.length;
          } else {
            // Create a Digest Update (simple) when the command fills entirely the SAM buffer
            samCommands.add(new CommandDigestUpdate(getContext(), false, cardApdu));
          }
        }
        if (i != 0) {
          // Add command
          samCommands.add(new CommandDigestUpdateMultiple(getContext(), Arrays.copyOf(buffer, i)));
        }
      } else {
        // Digest Update (simple)
        for (byte[] cardApdu : cardApdus) {
          samCommands.add(new CommandDigestUpdate(getContext(), false, cardApdu));
        }
      }
    }

    /** Prepares the "Digest Close" SAM command. */
    private void prepareDigestClose() {
      // CL-SAM-DCLOSE.1
      samCommands.add(new CommandDigestClose(getContext(), isExtendedModeRequired ? 8 : 4));
    }
  }

  private static final class InvalidCardMacException extends RuntimeException {
    private InvalidCardMacException(String message) {
      super(message);
    }
  }
}
