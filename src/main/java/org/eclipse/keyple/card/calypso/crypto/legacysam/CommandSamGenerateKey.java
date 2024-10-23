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

import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keypop.card.ApduResponseApi;

/**
 * Builds the Give Random APDU command.
 *
 * @since 0.9.0
 */
final class CommandSamGenerateKey extends Command {

  private byte[] cipheredData;

  /**
   * Instantiates a new CmdSamDigestUpdate and generate the ciphered data for a key ciphered by
   * another.
   *
   * <p>If bot KIF and KVC of the ciphering are equal to 0, the source key is ciphered with the null
   * key.
   *
   * @param context The command context.
   * @param targetKeyReference The target key reference.
   * @param cipheringKvc The KVC of the ciphering key.
   * @param sourceKif The KIF of the source key.
   * @param sourceKvc The KVC of the source key.
   * @param isTransferredObjectDiversified true if the transferred object (key or lock) is
   *     diversified.
   * @param arbitraryDiversifier null or the 8-byte diversifier to use.
   * @since 0.9.0
   */
  CommandSamGenerateKey(
      DtoAdapters.CommandContextDto context,
      byte targetKeyReference,
      byte cipheringKvc,
      byte sourceKif,
      byte sourceKvc,
      byte[] keyParameters,
      boolean isTransferredObjectDiversified,
      byte[] arbitraryDiversifier) {

    super(CommandRef.SAM_GENERATE_KEY, 48, context);

    byte cla = context.getTargetSam().getClassByte();

    byte p1 = (byte) (isTransferredObjectDiversified ? 0x01 : 0x00);
    byte[] dataIn = new byte[arbitraryDiversifier == null ? 13 : 13 + 8];
    dataIn[0] = cipheringKvc;
    dataIn[1] = sourceKif;
    dataIn[2] = sourceKvc;
    System.arraycopy(keyParameters, 0, dataIn, 3, 10);
    if (arbitraryDiversifier != null) {
      System.arraycopy(arbitraryDiversifier, 0, dataIn, 13, 8);
    }

    setApduRequest(
        new DtoAdapters.ApduRequestAdapter(
            ApduUtil.build(
                cla, getCommandRef().getInstructionByte(), p1, targetKeyReference, dataIn, null)));
  }

  /**
   * Gets the 32 bytes of ciphered data.
   *
   * @return the ciphered data byte array or null if the operation failed
   * @since 0.9.0
   */
  byte[] getCipheredData() {
    return cipheredData;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  void finalizeRequest() {
    /* nothing to do */
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  boolean isControlSamRequiredToFinalizeRequest() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  void parseResponse(ApduResponseApi apduResponse) throws CommandException {
    setResponseAndCheckStatus(apduResponse);
    cipheredData = apduResponse.getDataOut();
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }
}
