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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.calypso.crypto.legacysam.transaction.InvalidSignatureException;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * Builds the "Data Cipher" SAM command.
 *
 * @since 0.1.0
 */
final class CommandDataCipher extends Command {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<Integer, StatusProperties>(Command.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", IllegalParameterException.class));
    m.put(
        0x6900,
        new StatusProperties(
            "An event counter cannot be incremented.", CounterOverflowException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Preconditions not satisfied:\n"
                + "- The SAM is locked.\n"
                + "- Cipher or sign forbidden (DataCipherEnableBit of PAR5 is 0).\n"
                + "- Ciphering or signing mode, and ciphering forbidden (CipherEnableBit of PAR1 is 0).\n"
                + "- Decipher mode, and deciphering forbidden (DecipherDataEnableBit of PAR1 is 0).\n"
                + "- AES key.",
            AccessForbiddenException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found: ciphering key not found.", DataAccessException.class));
    m.put(0x6B00, new StatusProperties("Incorrect P1.", IllegalParameterException.class));
    STATUS_TABLE = m;
  }

  private final BasicSignatureComputationDataAdapter signatureComputationData;
  private final BasicSignatureVerificationDataAdapter signatureVerificationData;

  /**
   * Instantiates a new instance based on the provided data.
   *
   * @param context The command context.
   * @param signatureComputationData The signature computation data (optional).
   * @param signatureVerificationData The signature computation data (optional).
   * @since 0.1.0
   */
  CommandDataCipher(
      CommandContextDto context,
      BasicSignatureComputationDataAdapter signatureComputationData,
      BasicSignatureVerificationDataAdapter signatureVerificationData) {

    super(CommandRef.DATA_CIPHER, 0, context);

    this.signatureComputationData = signatureComputationData;
    this.signatureVerificationData = signatureVerificationData;

    final byte cla = context.getTargetSam().getClassByte();
    final byte inst = getCommandRef().getInstructionByte();
    final byte p1 = (byte) 0x40; // TODO implement the other modes (cipher, decipher)
    final byte p2 = (byte) 0x00;

    final byte[] dataIn;
    if (signatureComputationData != null) {
      dataIn = new byte[2 + signatureComputationData.getData().length];
      dataIn[0] = signatureComputationData.getKif();
      dataIn[1] = signatureComputationData.getKvc();
      System.arraycopy(
          signatureComputationData.getData(),
          0,
          dataIn,
          2,
          signatureComputationData.getData().length);
    } else if (signatureVerificationData != null) {
      dataIn = new byte[2 + signatureVerificationData.getData().length];
      dataIn[0] = signatureVerificationData.getKif();
      dataIn[1] = signatureVerificationData.getKvc();
      System.arraycopy(
          signatureVerificationData.getData(),
          0,
          dataIn,
          2,
          signatureVerificationData.getData().length);
    } else {
      dataIn = null;
    }

    setApduRequest(new ApduRequestAdapter(ApduUtil.build(cla, inst, p1, p2, dataIn, null)));
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
    if (apduResponse.getDataOut().length > 0) {
      if (signatureComputationData != null) {
        signatureComputationData.setSignature(
            Arrays.copyOfRange(
                apduResponse.getDataOut(), 0, signatureComputationData.getSignatureSize()));
      } else if (signatureVerificationData != null) {
        byte[] computedSignature =
            Arrays.copyOfRange(
                apduResponse.getDataOut(), 0, signatureVerificationData.getSignature().length);
        signatureVerificationData.setSignatureValid(
            Arrays.equals(computedSignature, signatureVerificationData.getSignature()));
      }
      if (signatureVerificationData != null && !signatureVerificationData.isSignatureValid()) {
        throw new InvalidSignatureException("Invalid signature.");
      }
    }
  }
}
