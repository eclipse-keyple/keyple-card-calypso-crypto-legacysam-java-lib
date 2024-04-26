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
import static org.eclipse.keyple.card.calypso.crypto.legacysam.LegacySamConstants.TagInfo.CARD_PUBLIC_KEY_DATA;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.LegacyCardCertificateComputationData;
import org.eclipse.keypop.card.ApduResponseApi;

/**
 * Builds the "PSO Compute Certificate" SAM command.
 *
 * @since 0.6.0
 */
final class CommandPsoComputeCertificate extends Command {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<>(Command.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc", IllegalParameterException.class));
    m.put(
        0x6900,
        new StatusProperties(
            "An event counter cannot be incremented", CounterOverflowException.class));
    m.put(
        0x6985,
        new StatusProperties("Preconditions not satisfied", AccessForbiddenException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Incorrect value in the incoming data", IncorrectInputDataException.class));
    m.put(
        0x6A88,
        new StatusProperties(
            "Unknown incoming data object (incorrect tag)", DataAccessException.class));
    m.put(0x6B00, new StatusProperties("Incorrect P1 or P2", IllegalParameterException.class));
    STATUS_TABLE = m;
  }

  private final LegacyCardCertificateComputationDataAdapter data;

  /**
   * Instantiates a new instance based on the provided "Card Public Key Data" data object.
   *
   * <p>The "Card Public Key Data" data object (tag DF25) is a byte array containing the certificate
   * metadata and optionally the card ECC public key.
   *
   * @param context The command context.
   * @param data A byte array of length 66 or 130 depending on whether the ECC key is included or
   *     not.
   * @since 0.1.0
   */
  CommandPsoComputeCertificate(
      CommandContextDto context, LegacyCardCertificateComputationData data) {

    super(
        CommandRef.PSO_COMPUTE_CERTIFICATE,
        LegacySamConstants.TagInfo.GENERATED_CARD_CERTIFICATE.getTotalLength(),
        context);
    this.data = (LegacyCardCertificateComputationDataAdapter) data;

    final byte cla = context.getTargetSam().getClassByte();
    final byte inst = getCommandRef().getInstructionByte();
    final byte p1 = (byte) 0xEE;
    final byte p2 = (byte) 0xAC;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, inst, p1, p2, generateCardPublicKeyData(this.data), (byte) 0xFF)));
  }

  /**
   * Generates the public key data for the card certificate generation.
   *
   * @return A byte array containing the public key data.
   */
  private byte[] generateCardPublicKeyData(LegacyCardCertificateComputationDataAdapter data) {
    // BER-TLV header
    byte[] header = CARD_PUBLIC_KEY_DATA.getHeader();
    // allocate buffer size according to the presence of cardPublicKey, adjust length byte
    // accordingly
    ByteBuffer cardPublicKeyData;
    if (data.getCardPublicKey() == null) {
      cardPublicKeyData = ByteBuffer.allocate(66);
    } else {
      cardPublicKeyData = ByteBuffer.allocate(66 + LegacySamConstants.ECC_PUBLIC_KEY_SIZE);
      header[2] = 127; // change default length
    }
    cardPublicKeyData.put(header);
    // AID length
    cardPublicKeyData.put((byte) data.getAid().length);
    // AID
    cardPublicKeyData.put(data.getAid());
    // AID padding
    cardPublicKeyData.position(
        cardPublicKeyData.position() + LegacySamConstants.AID_SIZE_MAX - data.getAid().length);
    // serial number
    cardPublicKeyData.put(data.getSerialNumber());
    // RFU
    cardPublicKeyData.putInt(0);
    // start date
    cardPublicKeyData.putInt((int) data.getStartDateBcd());
    // end date
    cardPublicKeyData.putInt((int) data.getEndDateBcd());
    // Rights (RFU)
    cardPublicKeyData.put((byte) 0);
    // Startup information
    cardPublicKeyData.put(data.getStartupInfo());
    // RFU
    cardPublicKeyData.put(new byte[18]);
    // public key if provided
    if (data.getCardPublicKey() != null) {
      cardPublicKeyData.put(data.getCardPublicKey());
    }
    return cardPublicKeyData.array();
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
    byte[] dataOut = apduResponse.getDataOut();
    if (dataOut.length > 0) {
      // check BER-TLV header
      byte[] header = LegacySamConstants.TagInfo.GENERATED_CARD_CERTIFICATE.getHeader();
      for (int i = 0; i < header.length; i++) {
        if (dataOut[i] != header[i]) {
          throw new DataAccessException("Inconsistent BER-TLV tag");
        }
      }
      data.setCertificate(Arrays.copyOfRange(dataOut, header.length, dataOut.length));
    }
  }
}
