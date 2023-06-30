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

import static org.eclipse.keyple.card.calypso.crypto.legacysam.DtoAdapters.ApduRequestAdapter;

import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keypop.card.ApduResponseApi;

/**
 * Builds a "SAM Cipher" command ("SAM Cipher CAAD", "SAM Cipher Ceilings", "SAM Cipher
 * Parameters").
 *
 * <p>The purpose is to compute the encrypted block to provide as input to the associated "write"
 * commands.
 *
 * @since 0.3.0
 */
final class CommandSamDataCipher extends Command {
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
                + "- Ciphering key: ciphering forbidden (CipherEnableBit of PAR1 is 0).",
            AccessForbiddenException.class));
    m.put(
        0x6A00,
        new StatusProperties("Incorrect P1 (!=%0xxxxx0) or P2.", IllegalParameterException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found: key to read not found.", DataAccessException.class));
    STATUS_TABLE = m;
  }

  private final byte[] cipheredData = new byte[48];

  /**
   * Instantiates a new instance to cipher a data record.
   *
   * @param context The command context.
   * @param recordNumber The targeted record number (in range [1..7], ignored when DataType is
   *     {@link DataType#ONE_CEILING_VALUE} or {@link DataType#PARAMETERS_RECORD}).
   * @param dataType The type of data to be ciphered.
   * @param plainData The data to be ciphered, preceded by a byte containing the encryption key KVC
   *     (30 bytes). bytes).
   * @since 0.3.0
   */
  CommandSamDataCipher(
      DtoAdapters.CommandContextDto context,
      int recordNumber,
      DataType dataType,
      byte[] plainData) {

    super(CommandRef.SAM_DATA_CIPHER, 48, context);

    byte cla = context.getTargetSam().getClassByte();
    byte inst = getCommandRef().getInstructionByte();
    final byte p1 = 0;
    byte p2;
    switch (dataType) {
      case CAAD_RECORD:
        p2 = (byte) (0xE7 + recordNumber);
        break;
      case CEILINGS_FILE_RECORD:
        p2 = (byte) (0xB1 + recordNumber);
        break;
      case ONE_CEILING_VALUE:
        p2 = (byte) 0xB8;
        break;
      case PARAMETERS_RECORD:
        p2 = (byte) 0xA0;
        break;
      default:
        throw new IllegalArgumentException("Invalid DataType: " + dataType);
    }
    setApduRequest(new ApduRequestAdapter(ApduUtil.build(cla, inst, p1, p2, plainData, null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
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
    System.arraycopy(apduResponse.getApdu(), 0, cipheredData, 0, 48);
  }

  /**
   * Retrieves the ciphered data resulting of the execution of the command.
   *
   * @return A 48-byte byte array.
   */
  byte[] getCipheredData() {
    return cipheredData;
  }

  /**
   * Enum to represent the different types of data that can be ciphered.
   *
   * @since 0.3.0
   */
  enum DataType {
    /**
     * The data is a CAAD record.
     *
     * @since 0.3.0
     */
    CAAD_RECORD,

    /**
     * The data is a ceilings file record.
     *
     * @since 0.3.0
     */
    CEILINGS_FILE_RECORD,

    /**
     * The data is a single ceiling value.
     *
     * @since 0.3.0
     */
    ONE_CEILING_VALUE,

    /**
     * The data is a parameters record.
     *
     * @since 0.3.0
     */
    PARAMETERS_RECORD
  }
}
