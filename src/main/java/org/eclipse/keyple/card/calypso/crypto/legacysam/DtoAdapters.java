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

import java.time.LocalDate;
import java.util.*;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keyple.core.util.json.JsonUtil;
import org.eclipse.keypop.calypso.crypto.legacysam.SystemKeyType;
import org.eclipse.keypop.calypso.crypto.legacysam.spi.LegacySamRevocationServiceSpi;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.*;
import org.eclipse.keypop.card.ProxyReaderApi;
import org.eclipse.keypop.card.spi.ApduRequestSpi;
import org.eclipse.keypop.card.spi.CardRequestSpi;
import org.eclipse.keypop.card.spi.CardSelectionRequestSpi;

/**
 * Contains all DTO adapters.
 *
 * @since 0.1.0
 */
final class DtoAdapters {
  private static final String MSG_THE_COMMAND_HAS_NOT_YET_BEEN_PROCESSED =
      "The command has not yet been processed";

  private DtoAdapters() {}

  /**
   * Adapter of {@link SignatureComputationData}.
   *
   * @param <T> The type of the lowest level child object.
   * @since 0.1.0
   */
  abstract static class SignatureComputationDataAdapter<T extends SignatureComputationData<T>>
      implements SignatureComputationData<T> {

    private final T currentInstance = (T) this;
    private byte[] data;
    private byte kif;
    private byte kvc;
    private int signatureSize = 8;
    private byte[] keyDiversifier;
    private byte[] signature;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    @Override
    public final T setData(byte[] data, byte kif, byte kvc) {
      this.data = data;
      this.kif = kif;
      this.kvc = kvc;
      return currentInstance;
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    @Override
    public final T setSignatureSize(int size) {
      signatureSize = size;
      return currentInstance;
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    @Override
    public final T setKeyDiversifier(byte[] diversifier) {
      keyDiversifier = diversifier;
      return currentInstance;
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    @Override
    public final byte[] getSignature() {
      if (signature == null) {
        throw new IllegalStateException(MSG_THE_COMMAND_HAS_NOT_YET_BEEN_PROCESSED);
      }
      return signature;
    }

    /**
     * @return A not empty array of data. It is required to check input data first.
     * @since 0.1.0
     */
    final byte[] getData() {
      return data;
    }

    /**
     * @return The KIF. It is required to check input data first.
     * @since 0.1.0
     */
    final byte getKif() {
      return kif;
    }

    /**
     * @return The KVC. It is required to check input data first.
     * @since 0.1.0
     */
    final byte getKvc() {
      return kvc;
    }

    /**
     * @return The signature size.
     * @since 0.1.0
     */
    final int getSignatureSize() {
      return signatureSize;
    }

    /**
     * @return Null if the key diversifier is not set.
     * @since 0.1.0
     */
    final byte[] getKeyDiversifier() {
      return keyDiversifier;
    }

    /**
     * Sets the computed signature.
     *
     * @param signature The computed signature.
     * @since 0.1.0
     */
    final void setSignature(byte[] signature) {
      this.signature = signature;
    }
  }

  /**
   * Adapter of {@link SignatureVerificationData}.
   *
   * @param <T> The type of the lowest level child object.
   * @since 0.1.0
   */
  abstract static class SignatureVerificationDataAdapter<T extends SignatureVerificationData<T>>
      implements SignatureVerificationData<T> {

    private final T currentInstance = (T) this;
    protected SamTraceabilityMode samTraceabilityMode;
    private byte[] data;
    private byte[] signature;
    private byte kif;
    private byte kvc;
    private byte[] keyDiversifier;
    private Boolean isSignatureValid;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    @Override
    public final T setData(byte[] data, byte[] signature, byte kif, byte kvc) {
      this.data = data;
      this.signature = signature;
      this.kif = kif;
      this.kvc = kvc;
      return currentInstance;
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    @Override
    public final T setKeyDiversifier(byte[] diversifier) {
      keyDiversifier = diversifier;
      return currentInstance;
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    @Override
    public final boolean isSignatureValid() {
      if (isSignatureValid == null) {
        throw new IllegalStateException(MSG_THE_COMMAND_HAS_NOT_YET_BEEN_PROCESSED);
      }
      return isSignatureValid;
    }

    /**
     * @return A not empty array of data. It is required to check input data first.
     * @since 0.1.0
     */
    final byte[] getData() {
      return data;
    }

    /**
     * @return A not empty array of the signature to check. It is required to check input data
     *     first.
     * @since 0.1.0
     */
    final byte[] getSignature() {
      return signature;
    }

    /**
     * @return The KIF. It is required to check input data first.
     * @since 0.1.0
     */
    final byte getKif() {
      return kif;
    }

    /**
     * @return The KVC. It is required to check input data first.
     * @since 0.1.0
     */
    final byte getKvc() {
      return kvc;
    }

    /**
     * @return Null if the key diversifier is not set.
     * @since 0.1.0
     */
    final byte[] getKeyDiversifier() {
      return keyDiversifier;
    }

    /**
     * Sets the signature verification status.
     *
     * @param isSignatureValid True if the signature is valid.
     * @since 0.1.0
     */
    final void setSignatureValid(boolean isSignatureValid) {
      this.isSignatureValid = isSignatureValid;
    }
  }

  /**
   * Adapter of {@link BasicSignatureComputationData}.
   *
   * @since 0.1.0
   */
  static class BasicSignatureComputationDataAdapter
      extends SignatureComputationDataAdapter<BasicSignatureComputationData>
      implements BasicSignatureComputationData {}

  /**
   * Adapter of {@link BasicSignatureVerificationData}.
   *
   * @since 0.1.0
   */
  static class BasicSignatureVerificationDataAdapter
      extends SignatureVerificationDataAdapter<BasicSignatureVerificationData>
      implements BasicSignatureVerificationData {}

  /**
   * Adapter of {@link TraceableSignatureComputationData}.
   *
   * @since 0.1.0
   */
  static final class TraceableSignatureComputationDataAdapter
      extends SignatureComputationDataAdapter<TraceableSignatureComputationData>
      implements TraceableSignatureComputationData {

    private boolean isSamTraceabilityMode;
    private int traceabilityOffset;
    private boolean isBusyMode = true;
    private byte[] signedData;
    private SamTraceabilityMode samTraceabilityMode;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    @Override
    public TraceableSignatureComputationData withSamTraceabilityMode(
        int offset, SamTraceabilityMode samTraceabilityMode) {
      Assert.getInstance().notNull(samTraceabilityMode, "samTraceabilityMode");
      isSamTraceabilityMode = true;
      traceabilityOffset = offset;
      this.samTraceabilityMode = samTraceabilityMode;
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    @Override
    public TraceableSignatureComputationData withoutBusyMode() {
      isBusyMode = false;
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    @Override
    public byte[] getSignedData() {
      if (signedData == null) {
        throw new IllegalStateException(MSG_THE_COMMAND_HAS_NOT_YET_BEEN_PROCESSED);
      }
      return signedData;
    }

    /**
     * @return True if the "SAM traceability" mode is enabled.
     * @since 0.1.0
     */
    boolean isSamTraceabilityMode() {
      return isSamTraceabilityMode;
    }

    /**
     * @return The offset associated to the "SAM traceability" mode. It is required to check if the
     *     "SAM traceability" mode is enabled first.
     * @since 0.1.0
     */
    int getTraceabilityOffset() {
      return traceabilityOffset;
    }

    /**
     * @return the "SAM traceability" mode. It is required to check if the "SAM traceability" mode
     *     is enabled first.
     * @since 0.1.0
     */
    SamTraceabilityMode getSamTraceabilityMode() {
      return samTraceabilityMode;
    }

    /**
     * @return True if the "Busy" mode is enabled.
     * @since 0.1.0
     */
    boolean isBusyMode() {
      return isBusyMode;
    }

    /**
     * Sets the data used for signature computation.
     *
     * @param signedData The signed data.
     * @since 0.1.0
     */
    void setSignedData(byte[] signedData) {
      this.signedData = signedData;
    }
  }

  /**
   * Adapter of {@link TraceableSignatureVerificationData}.
   *
   * @since 0.1.0
   */
  static final class TraceableSignatureVerificationDataAdapter
      extends SignatureVerificationDataAdapter<TraceableSignatureVerificationData>
      implements TraceableSignatureVerificationData {

    private boolean isSamTraceabilityMode;
    private int traceabilityOffset;
    private LegacySamRevocationServiceSpi samRevocationService;
    private boolean isBusyMode = true;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    @Override
    public TraceableSignatureVerificationData withSamTraceabilityMode(
        int offset,
        SamTraceabilityMode samTraceabilityMode,
        LegacySamRevocationServiceSpi samRevocationService) {
      Assert.getInstance().notNull(samTraceabilityMode, "samTraceabilityMode");
      isSamTraceabilityMode = true;
      traceabilityOffset = offset;
      this.samTraceabilityMode = samTraceabilityMode;
      this.samRevocationService = samRevocationService;
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    @Override
    public TraceableSignatureVerificationData withoutBusyMode() {
      isBusyMode = false;
      return this;
    }

    /**
     * @return True if the "SAM traceability" mode is enabled.
     * @since 0.1.0
     */
    boolean isSamTraceabilityMode() {
      return isSamTraceabilityMode;
    }

    /**
     * @return The offset associated to the "SAM traceability" mode. It is required to check if the
     *     "SAM traceability" mode is enabled first.
     * @since 0.1.0
     */
    int getTraceabilityOffset() {
      return traceabilityOffset;
    }

    /**
     * @return the "SAM traceability" mode. It is required to check if the "SAM traceability" mode
     *     is enabled first.
     * @since 0.1.0
     */
    SamTraceabilityMode getSamTraceabilityMode() {
      return samTraceabilityMode;
    }

    /**
     * @return The SAM revocation service or null if the verification of the SAM revocation status
     *     is not requested. It is required to check if the "SAM traceability" mode is enabled
     *     first.
     * @since 0.1.0
     */
    LegacySamRevocationServiceSpi getSamRevocationService() {
      return samRevocationService;
    }

    /**
     * @return True if the "Busy" mode is enabled.
     * @since 0.1.0
     */
    boolean isBusyMode() {
      return isBusyMode;
    }
  }

  /**
   * This POJO contains a set of data related to an ISO-7816 APDU command.
   *
   * <ul>
   *   <li>A byte array containing the raw APDU data.
   *   <li>A flag indicating if the APDU is of type 4 (ingoing and outgoing data).
   *   <li>An optional set of integers corresponding to valid status words in response to this APDU.
   * </ul>
   *
   * Attaching an optional name to the request facilitates the enhancement of the application logs
   * using the toString method.
   *
   * @since 0.1.0
   */
  static final class ApduRequestAdapter implements ApduRequestSpi {

    private static final int DEFAULT_SUCCESSFUL_CODE = 0x9000;

    private final byte[] apdu;
    private final Set<Integer> successfulStatusWords;
    private String info;

    /**
     * Builds an APDU request from a raw byte buffer.
     *
     * <p>The default status words list is initialized with the standard successful code 9000h.
     *
     * @param apdu The bytes of the APDU's body.
     * @since 0.1.0
     */
    ApduRequestAdapter(byte[] apdu) {
      this.apdu = apdu;
      successfulStatusWords = new HashSet<>();
      successfulStatusWords.add(DEFAULT_SUCCESSFUL_CODE);
    }

    /**
     * Adds a status word to the list of those that should be considered successful for the APDU.
     *
     * <p>Note: initially, the list contains the standard successful status word {@code 9000h}.
     *
     * @param successfulStatusWord A positive int &le; {@code FFFFh}.
     * @return The object instance.
     * @since 0.1.0
     */
    ApduRequestAdapter addSuccessfulStatusWord(int successfulStatusWord) {
      successfulStatusWords.add(successfulStatusWord);
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    @Override
    public Set<Integer> getSuccessfulStatusWords() {
      return successfulStatusWords;
    }

    /**
     * Names the APDU request.
     *
     * <p>This string is dedicated to improve the readability of logs and should therefore only be
     * invoked conditionally (e.g. when log level &gt;= debug).
     *
     * @param info The request name (free text).
     * @return The object instance.
     * @since 0.1.0
     */
    ApduRequestAdapter setInfo(String info) {
      this.info = info;
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    @Override
    public String getInfo() {
      return info;
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    @Override
    public byte[] getApdu() {
      return apdu;
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    @Override
    public String toString() {
      return "ApduRequestAdapter{"
          + "apdu='"
          + HexUtil.toHex(apdu)
          + '\''
          + ", successfulStatusWords="
          + JsonUtil.toJson(successfulStatusWords)
          + ", info='"
          + info
          + '\''
          + '}';
    }
  }

  /**
   * This POJO contains an ordered list of {@link ApduRequestSpi} and the associated status code
   * check policy.
   *
   * @since 0.1.0
   */
  static final class CardRequestAdapter implements CardRequestSpi {

    private final List<ApduRequestSpi> apduRequests;
    private final boolean stopOnUnsuccessfulStatusWord;

    /**
     * Builds a card request with a list of {@link ApduRequestSpi } and the flag indicating the
     * expected response checking behavior.
     *
     * <p>When the status code verification is enabled, the transmission of the APDUs must be
     * interrupted as soon as the status code of a response is unexpected.
     *
     * @param apduRequests A not empty list.
     * @param stopOnUnsuccessfulStatusWord true or false.
     * @since 0.1.0
     */
    CardRequestAdapter(List<ApduRequestSpi> apduRequests, boolean stopOnUnsuccessfulStatusWord) {
      this.apduRequests = apduRequests;
      this.stopOnUnsuccessfulStatusWord = stopOnUnsuccessfulStatusWord;
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    @Override
    public List<ApduRequestSpi> getApduRequests() {
      return apduRequests;
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    @Override
    public boolean stopOnUnsuccessfulStatusWord() {
      return stopOnUnsuccessfulStatusWord;
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    @Override
    public String toString() {
      return "CardRequestAdapter{"
          + "apduRequests="
          + apduRequests
          + ", stopOnUnsuccessfulStatusWord="
          + stopOnUnsuccessfulStatusWord
          + '}';
    }
  }

  /**
   * This POJO contains the data used to define a selection extension containing additional APDU
   * commands to be sent to the card when the selection is successful.
   *
   * @since 0.1.0
   */
  static final class CardSelectionRequestAdapter implements CardSelectionRequestSpi {

    private static final int DEFAULT_SUCCESSFUL_CODE = 0x9000;
    private final CardRequestSpi cardRequest;
    private final Set<Integer> successfulSelectionStatusWords;

    /**
     * Builds a card selection request to open a logical channel with additional APDUs to be sent
     * after the selection step.
     *
     * @param cardRequest The card request.
     * @since 0.1.0
     */
    CardSelectionRequestAdapter(CardRequestSpi cardRequest) {
      this.cardRequest = cardRequest;
      successfulSelectionStatusWords = new LinkedHashSet<>(1);
      successfulSelectionStatusWords.add(DEFAULT_SUCCESSFUL_CODE);
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    @Override
    public Set<Integer> getSuccessfulSelectionStatusWords() {
      return successfulSelectionStatusWords;
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    @Override
    public CardRequestSpi getCardRequest() {
      return cardRequest;
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    @Override
    public String toString() {
      return "CardSelectionRequestAdapter{"
          + "cardRequest="
          + cardRequest
          + ", successfulSelectionStatusWords="
          + JsonUtil.toJson(successfulSelectionStatusWords)
          + '}';
    }
  }

  /**
   * This POJO contains the target SAM context data used when doing asynchronous transactions.
   *
   * @since 0.3.0
   */
  static final class TargetSamContextDto {

    private final byte[] serialNumber;
    private final boolean isDynamicMode;
    private final Map<SystemKeyType, Integer> systemKeyTypeToCounterNumberMap =
        //  enummap is not suitable for the gson serializer
        new HashMap<>(3); // NOSONAR
    private final Map<SystemKeyType, Byte> systemKeyTypeToKvcMap =
        //  enummap is not suitable for the gson serializer
        new HashMap<>(3); // NOSONAR
    private final Map<Integer, Integer> counterNumberToCounterValueMap = new HashMap<>(3);

    /**
     * Constructs a new instance with the specified serial number and dynamic mode flag.
     *
     * @param serialNumber The serial number of the target SAM.
     * @param isDynamicMode A boolean indicating whether the target SAM is operating in dynamic
     *     mode.
     * @since 0.3.0
     */
    TargetSamContextDto(byte[] serialNumber, boolean isDynamicMode) {
      this.serialNumber = serialNumber;
      this.isDynamicMode = isDynamicMode;
    }

    /**
     * Returns the serial number of the target SAM.
     *
     * @return a byte array containing the serial number of the target SAM.
     * @since 0.3.0
     */
    byte[] getSerialNumber() {
      return serialNumber;
    }

    /**
     * Returns a boolean indicating whether the target SAM is operating in dynamic mode.
     *
     * @return True if the target SAM is operating in dynamic mode, otherwise false.
     * @since 0.3.0
     */
    boolean isDynamicMode() {
      return isDynamicMode;
    }

    /**
     * Returns a map containing the system key types and their corresponding counter numbers.
     *
     * @return A map.
     * @since 0.3.0
     */
    Map<SystemKeyType, Integer> getSystemKeyTypeToCounterNumberMap() {
      return systemKeyTypeToCounterNumberMap;
    }

    /**
     * Returns a map containing the system key types and their corresponding KVCs.
     *
     * @return A map.
     * @since 0.3.0
     */
    Map<SystemKeyType, Byte> getSystemKeyTypeToKvcMap() {
      return systemKeyTypeToKvcMap;
    }

    /**
     * Returns a map containing the counter numbers and their corresponding counter values.
     *
     * @return A map.
     * @since 0.3.0
     */
    Map<Integer, Integer> getCounterNumberToCounterValueMap() {
      return counterNumberToCounterValueMap;
    }
  }

  /**
   * This POJO contains the command context for a SAM transaction and its related SAM commands.
   *
   * @since 0.3.0
   */
  static final class CommandContextDto {

    private final LegacySamAdapter targetSam;
    private final ProxyReaderApi controlSamReader;
    private final LegacySamAdapter controlSam;

    /**
     * Constructs a new instance with the specified target SAM, control SAM reader and control SAM.
     *
     * @param targetSam The target legacy SAM.
     * @param controlSamReader The reader through which the control SAM communicates.
     * @param controlSam The control legacy SAM.
     * @since 0.3.0
     */
    CommandContextDto(
        LegacySamAdapter targetSam, ProxyReaderApi controlSamReader, LegacySamAdapter controlSam) {
      this.targetSam = targetSam;
      this.controlSamReader = controlSamReader;
      this.controlSam = controlSam;
    }

    /**
     * @return The target SAM.
     * @since 0.3.0
     */
    LegacySamAdapter getTargetSam() {
      return targetSam;
    }

    /**
     * @return The control SAM reader.
     * @since 0.3.0
     */
    ProxyReaderApi getControlSamReader() {
      return controlSamReader;
    }

    /**
     * @return The control SAM.
     * @since 0.3.0
     */
    LegacySamAdapter getControlSam() {
      return controlSam;
    }
  }

  /**
   * This POJO contains an ECC key pair generated by the SAM.
   *
   * @since 0.6.0
   */
  static class KeyPairContainerAdapter implements KeyPairContainer {
    private byte[] keyPair;

    /**
     * {@inheritDoc}
     *
     * @since 0.6.0
     */
    @Override
    public byte[] getKeyPair() {
      return keyPair;
    }

    /**
     * Sets the key pair value.
     *
     * @param keyPair A 96-byte byte array.
     * @since 0.6.0
     */
    void setKeyPair(byte[] keyPair) {
      this.keyPair = keyPair;
    }
  }

  /**
   * This POJO contains all data expected by the SAM to compute a card certificate.
   *
   * @since 0.6.0
   */
  static class LegacyCardCertificateComputationDataAdapter
      implements LegacyCardCertificateComputationData {

    private byte[] cardPublicKey;
    private long startDateBcd;
    private long endDateBcd;
    private byte[] aid;
    private byte[] serialNumber;
    private byte[] startupInfo;
    private byte[] certificate;

    /**
     * {@inheritDoc}
     *
     * @since 0.6.0
     */
    @Override
    public LegacyCardCertificateComputationData setCardPublicKey(byte[] cardPublicKey) {
      Assert.getInstance()
          .notNull(cardPublicKey, "cardPublicKey")
          .isEqual(cardPublicKey.length, 64, "cardPublicKey");
      this.cardPublicKey = cardPublicKey;
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.6.0
     */
    @Override
    public LegacyCardCertificateComputationData setStartDate(LocalDate startDate) {
      Assert.getInstance().notNull(startDate, "startDate");
      startDateBcd =
          LegacySamUtil.convertDateToBcdLong(
              startDate.getYear(), startDate.getMonthValue(), startDate.getDayOfMonth());
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.6.0
     */
    @Override
    public LegacyCardCertificateComputationData setEndDate(LocalDate endDate) {
      Assert.getInstance().notNull(endDate, "endDate");
      endDateBcd =
          LegacySamUtil.convertDateToBcdLong(
              endDate.getYear(), endDate.getMonthValue(), endDate.getDayOfMonth());
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.6.0
     */
    @Override
    public LegacyCardCertificateComputationData setCardAid(byte[] aid) {
      Assert.getInstance().notNull(aid, "aid").isInRange(aid.length, 5, 16, "aid length");
      this.aid = aid;
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.6.0
     */
    @Override
    public LegacyCardCertificateComputationData setCardSerialNumber(byte[] serialNumber) {
      Assert.getInstance()
          .notNull(serialNumber, "serialNumber")
          .isEqual(serialNumber.length, 8, "serialNumber length");
      this.serialNumber = serialNumber;
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 0.6.0
     */
    @Override
    public LegacyCardCertificateComputationData setCardStartupInfo(byte[] startupInfo) {
      Assert.getInstance()
          .notNull(startupInfo, "startupInfo")
          .isEqual(startupInfo.length, 7, "startupInfo length");
      this.startupInfo = startupInfo;
      return this;
    }

    /**
     * @return The computed certificate.
     * @since 0.6.0
     */
    @Override
    public byte[] getCertificate() {
      return certificate;
    }

    /**
     * Sets the computed certificate.
     *
     * @param cardCertificate A 316-byte byte array.
     * @since 0.6.0
     */
    void setCertificate(byte[] cardCertificate) {
      this.certificate = cardCertificate;
    }

    /**
     * @return The card's public key or null if the key is not set.
     * @since 0.6.0
     */
    byte[] getCardPublicKey() {
      return cardPublicKey;
    }

    /**
     * @return The start date in BCD format.
     * @since 0.6.0
     */
    long getStartDateBcd() {
      return startDateBcd;
    }

    /**
     * @return The end date in BCD format.
     * @since 0.6.0
     */
    long getEndDateBcd() {
      return endDateBcd;
    }

    /**
     * @return The card AID.
     * @since 0.6.0
     */
    byte[] getAid() {
      return aid;
    }

    /**
     * @return The card serial number.
     * @since 0.6.0
     */
    byte[] getSerialNumber() {
      return serialNumber;
    }

    /**
     * @return The card startup information.
     * @since 0.6.0
     */
    byte[] getStartupInfo() {
      return startupInfo;
    }
  }
}
