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

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keyple.core.util.json.JsonUtil;
import org.eclipse.keypop.calypso.crypto.legacysam.CounterIncrementAccess;
import org.eclipse.keypop.calypso.crypto.legacysam.SystemKeyType;
import org.eclipse.keypop.calypso.crypto.legacysam.sam.KeyParameter;
import org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySam;
import org.eclipse.keypop.calypso.crypto.legacysam.sam.SamParameters;
import org.eclipse.keypop.card.CardSelectionResponseApi;
import org.eclipse.keypop.card.spi.SmartCardSpi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapter of {@link LegacySam}.
 *
 * @since 0.1.0
 */
final class LegacySamAdapter implements LegacySam, SmartCardSpi {

  private static final Logger logger = LoggerFactory.getLogger(LegacySamAdapter.class);

  private String powerOnData;
  private ProductType samProductType;
  private byte[] serialNumber;
  private byte platform;
  private byte applicationType;
  private byte applicationSubType;
  private byte softwareIssuer;
  private byte softwareVersion;
  private byte softwareRevision;
  private byte classByte;
  private final SortedMap<Integer, Integer> counters = new TreeMap<>();
  private final Map<Integer, CounterIncrementAccess> countersIncrementConfig = new HashMap<>();
  private final SortedMap<Integer, Integer> counterCeilings = new TreeMap<>();
  private final Map<SystemKeyType, KeyParameterAdapter> systemKeyParameterMap =
      new HashMap<>(); // NOSONAR JSON serializer
  private final Map<Integer, KeyParameterAdapter> workKeyParameterByRecordNumber = new HashMap<>();
  private final Map<Short, KeyParameterAdapter> workKeyParameterByKifKvc = new HashMap<>();
  private byte[] challenge;
  private byte[] caCertificate;
  private SamParametersAdapter samParameters;

  /**
   * Constructor
   *
   * <p>Create a {@link LegacySamAdapter} just containing the {@link ProductType}.
   *
   * @param productType The SAM product type.
   * @since 0.4.0
   */
  LegacySamAdapter(ProductType productType) {
    samProductType = productType;
    // CL-CLA-SAM.1
    classByte = computeClassByte(samProductType);
  }

  /**
   * Constructor
   *
   * <p>Create the initial content from the data received in response to the card selection.
   *
   * @param cardSelectionResponse the response to the selection command.
   * @since 0.1.0
   */
  LegacySamAdapter(CardSelectionResponseApi cardSelectionResponse) {
    parseSelectionResponse(cardSelectionResponse);
  }

  /**
   * Parses the selection response in order to determine all the SAM attributes from the power-on
   * data.
   *
   * @param cardSelectionResponse the response to the selection command.
   * @since 0.4.0
   */
  void parseSelectionResponse(CardSelectionResponseApi cardSelectionResponse) {
    // in the case of a SAM, the power-on data corresponds to the ATR of the card.
    powerOnData = cardSelectionResponse.getPowerOnData();
    if (powerOnData == null) {
      throw new IllegalStateException("ATR should not be empty");
    }

    serialNumber = new byte[4];

    /* extract the historical bytes from T3 to T12 */
    // CL-SAM-ATR.1
    String extractRegex = "3B(.{6}|.{10})805A(.{20})829000";
    Pattern pattern = Pattern.compile(extractRegex); // NOSONAR: hex strings here, regex is safe
    // to use
    Matcher matcher = pattern.matcher(powerOnData);
    if (matcher.find(0)) {
      byte[] atrSubElements = HexUtil.toByteArray(matcher.group(2));
      platform = atrSubElements[0];
      applicationType = atrSubElements[1];
      applicationSubType = atrSubElements[2];
      softwareIssuer = atrSubElements[3];
      softwareVersion = atrSubElements[4];
      softwareRevision = atrSubElements[5];

      // determine SAM product type from Application Subtype
      switch (applicationSubType) {
        case (byte) 0xC1:
          samProductType = softwareIssuer == (byte) 0x08 ? ProductType.HSM_C1 : ProductType.SAM_C1;
          break;
        case (byte) 0xD0:
        case (byte) 0xD1:
        case (byte) 0xD2:
        case (byte) 0xD3:
        case (byte) 0xD4:
        case (byte) 0xD5:
        case (byte) 0xD6:
        case (byte) 0xD7:
          samProductType = ProductType.SAM_S1DX;
          break;
        case (byte) 0xE1:
          samProductType = ProductType.SAM_S1E1;
          break;
        default:
          samProductType = ProductType.UNKNOWN;
          break;
      }

      System.arraycopy(atrSubElements, 6, serialNumber, 0, 4);
      if (logger.isTraceEnabled()) {
        logger.trace(
            "SAM {}, SERIAL_NUMBER={}h, PLATFORM={}h, APP_TYPE={}h, APP_SUBTYPE={}h, SW_ISSUER={}h, SW_VERSION={}h, SW_REVISION={}h",
            samProductType.name(),
            HexUtil.toHex(serialNumber),
            HexUtil.toHex(platform),
            HexUtil.toHex(applicationType),
            HexUtil.toHex(applicationSubType),
            HexUtil.toHex(softwareIssuer),
            HexUtil.toHex(softwareVersion),
            HexUtil.toHex(softwareRevision));
      }
    } else {
      samProductType = ProductType.UNKNOWN;
      platform = 0;
      applicationType = 0;
      applicationSubType = 0;
      softwareIssuer = 0;
      softwareVersion = 0;
      softwareRevision = 0;
    }
    // CL-CLA-SAM.1
    classByte = computeClassByte(samProductType);
  }

  private static byte computeClassByte(ProductType productType) {
    return productType == ProductType.SAM_S1DX ? (byte) 0x94 : (byte) 0x80;
  }

  /**
   * Gets the class byte to use for the current product type.
   *
   * @return A byte.
   * @since 0.1.0
   */
  byte getClassByte() {
    return classByte;
  }

  /**
   * Gets the maximum length allowed for digest commands.
   *
   * @return An positive int.
   * @since 0.1.0
   */
  int getMaxDigestDataLength() {
    switch (samProductType) {
      case SAM_C1:
      case HSM_C1:
        return 255;
      case SAM_S1DX:
        return 70;
      case SAM_S1E1:
        return 240;
      default:
        return 0;
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public String getPowerOnData() {
    return powerOnData;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public ProductType getProductType() {
    return samProductType;
  }

  /**
   * Gets textual information about the SAM.
   *
   * @return A not empty String.
   */
  @Override
  public String getProductInfo() {
    return "Type: " + samProductType.name() + ", S/N: " + HexUtil.toHex(getSerialNumber());
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte[] getSerialNumber() {
    return serialNumber;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte getPlatform() {
    return platform;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte getApplicationType() {
    return applicationType;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte getApplicationSubType() {
    return applicationSubType;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte getSoftwareIssuer() {
    return softwareIssuer;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte getSoftwareVersion() {
    return softwareVersion;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte getSoftwareRevision() {
    return softwareRevision;
  }

  /**
   * Adds or replace a counter value.
   *
   * @param counterNumber The number of the counter.
   * @param value The counter value.
   * @since 0.1.0
   */
  void putCounterValue(int counterNumber, int value) {
    counters.put(counterNumber, value);
  }

  /**
   * Adds or replace a counter ceiling value.
   *
   * @param counterNumber The number of the counter.
   * @param value The counter ceiling value.
   * @since 0.1.0
   */
  void putCounterCeilingValue(int counterNumber, int value) {
    counterCeilings.put(counterNumber, value);
  }

  /**
   * Adds or replace a counter increment configuration.
   *
   * @param counterNumber The number of the counter.
   * @param counterIncrementAccess The counter incrementing access.
   * @since 0.3.0
   */
  void putCounterIncrementConfiguration(
      int counterNumber, CounterIncrementAccess counterIncrementAccess) {
    countersIncrementConfig.put(counterNumber, counterIncrementAccess);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public Integer getCounter(int counterNumber) {
    return counters.get(counterNumber);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public SortedMap<Integer, Integer> getCounters() {
    return counters;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  public CounterIncrementAccess getCounterIncrementAccess(int counterNumber) {
    return countersIncrementConfig.get(counterNumber);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public Integer getCounterCeiling(int counterNumber) {
    return counterCeilings.get(counterNumber);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public SortedMap<Integer, Integer> getCounterCeilings() {
    return counterCeilings;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.6.0
   */
  @Override
  public byte[] getCaCertificate() {
    return caCertificate;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SamParameters getSamParameters() {
    return this.samParameters;
  }

  /**
   * Set the {@link KeyParameter} for specified {@link SystemKeyType}.
   *
   * @param samParameters The {@link SamParametersAdapter}.
   * @since 0.3.0
   */
  void setSamParameters(SamParametersAdapter samParameters) {
    this.samParameters = samParameters;
  }

  /**
   * Set the {@link KeyParameter} for specified {@link SystemKeyType}.
   *
   * @param systemKeyType The system key type.
   * @param keyParameter The {@link KeyParameterAdapter}.
   * @since 0.3.0
   */
  void setSystemKeyParameter(SystemKeyType systemKeyType, KeyParameterAdapter keyParameter) {
    systemKeyParameterMap.put(systemKeyType, keyParameter);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  public KeyParameter getSystemKeyParameter(SystemKeyType systemKeyType) {
    return systemKeyParameterMap.get(systemKeyType);
  }

  /**
   * Set the {@link KeyParameter} for work key identified by its record number.
   *
   * @param recordNumber The key record number.
   * @param keyParameter The {@link KeyParameterAdapter}.
   * @since 0.9.0
   */
  void setWorkKeyParameter(int recordNumber, KeyParameterAdapter keyParameter) {
    workKeyParameterByRecordNumber.put(recordNumber, keyParameter);
  }

  /**
   * Set the {@link KeyParameter} for work key identified by its KIF/KVC.
   *
   * @param kifKvc The combined KIF/KVC of the key.
   * @param keyParameter The {@link KeyParameterAdapter}.
   * @since 0.9.0
   */
  void setWorkKeyParameter(Short kifKvc, KeyParameterAdapter keyParameter) {
    workKeyParameterByKifKvc.put(kifKvc, keyParameter);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public KeyParameter getWorkKeyParameter(int recordNumber) {
    return workKeyParameterByRecordNumber.get(recordNumber);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public KeyParameter getWorkKeyParameter(byte kif, byte kvc) {
    return workKeyParameterByKifKvc.get((short) ((kif << 8) | (kvc & 0xFF)));
  }

  /**
   * Gets the object content as a Json string.
   *
   * @return A not empty string.
   * @since 0.1.0
   */
  @Override
  public String toString() {
    return JsonUtil.toJson(this);
  }

  /**
   * Sets the challenge.
   *
   * @since 0.3.0
   */
  void setChallenge(byte[] challenge) {
    this.challenge = challenge;
  }

  /**
   * Gets and resets the current challenge.
   *
   * @return Null if no challenge is available.
   * @since 0.4.0
   */
  byte[] popChallenge() {
    byte[] res = challenge;
    challenge = null;
    return res;
  }

  /**
   * Sets the CA certificate retrieved from the SAM.
   *
   * @param caCertificate The 384 bytes of the CA certificate.
   * @since 0.6.0
   */
  void setCaCertificate(byte[] caCertificate) {
    this.caCertificate = caCertificate;
  }
}
