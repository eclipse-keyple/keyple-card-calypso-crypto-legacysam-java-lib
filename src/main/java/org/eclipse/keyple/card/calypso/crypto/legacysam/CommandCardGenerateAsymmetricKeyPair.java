/* **************************************************************************************
 * Copyright (c) 2024 Calypso Networks Association https://calypsonet.org/
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

import static org.eclipse.keyple.card.calypso.crypto.legacysam.DtoAdapters.ApduRequestAdapter;
import static org.eclipse.keyple.card.calypso.crypto.legacysam.DtoAdapters.CommandContextDto;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.KeyPairContainer;
import org.eclipse.keypop.card.ApduResponseApi;

/**
 * Builds the "Card Generate Asymmetric Key Pair" SAM command.
 *
 * @since 0.6.0
 */
final class CommandCardGenerateAsymmetricKeyPair extends Command {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<>(Command.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", IllegalParameterException.class));
    m.put(
        0x6985,
        new StatusProperties("Preconditions not satisfied.", AccessForbiddenException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Incorrect value in the incoming data (OID unknown).",
            IncorrectInputDataException.class));
    m.put(0x6B00, new StatusProperties("Incorrect P1.", IllegalParameterException.class));
    STATUS_TABLE = m;
  }

  private final DtoAdapters.KeyPairContainerAdapter keyPairContainer;

  /**
   * Instantiates a new instance.
   *
   * <p>The OID of the key to generate is "06082A8648CE3D030107" (P-256 curve as referenced in FIPS
   * PUB 186-4 publication).
   *
   * @param context The command context.
   * @param keyPairContainer The key pair container.
   * @since 0.6.0
   */
  CommandCardGenerateAsymmetricKeyPair(
      CommandContextDto context, KeyPairContainer keyPairContainer) {

    super(CommandRef.CARD_GENERATE_ASYMMETRIC_KEY_PAIR, 0, context);
    this.keyPairContainer = (DtoAdapters.KeyPairContainerAdapter) keyPairContainer;

    final byte cla = context.getTargetSam().getClassByte();
    final byte inst = getCommandRef().getInstructionByte();
    final byte p1 = (byte) 0x80;
    final byte p2 = (byte) 0x00;
    final byte[] oid = HexUtil.toByteArray("06082A8648CE3D030107");

    setApduRequest(new ApduRequestAdapter(ApduUtil.build(cla, inst, p1, p2, oid, (byte) 0x63)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.6.0
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.6.0
   */
  @Override
  void finalizeRequest() {
    /* nothing to do */
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.6.0
   */
  @Override
  boolean isControlSamRequiredToFinalizeRequest() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.6.0
   */
  @Override
  void parseResponse(ApduResponseApi apduResponse) throws CommandException {
    setResponseAndCheckStatus(apduResponse);
    byte[] dataOut = apduResponse.getDataOut();
    if (dataOut.length > 0) {
      if (LegacySamConstants.TagInfo.GENERATED_CARD_ECC_KEY_PAIR.getLength() != dataOut.length) {
        // check BER-TLV header
        byte[] header = LegacySamConstants.TagInfo.GENERATED_CARD_ECC_KEY_PAIR.getHeader();
        for (int i = 0; i < header.length; i++) {
          if (dataOut[i] != header[i]) {
            throw new DataAccessException("Inconsistent BER-TLV tag");
          }
        }
        keyPairContainer.setKeyPair(Arrays.copyOfRange(dataOut, header.length, dataOut.length));
      } else {
        throw new UnexpectedResponseLengthException("Incorrect response length: " + dataOut.length);
      }
    }
  }
}
