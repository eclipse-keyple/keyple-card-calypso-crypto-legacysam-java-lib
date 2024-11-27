/* **************************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://calypsonet.org/
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
import static org.eclipse.keyple.card.calypso.crypto.legacysam.LegacySamConstants.RECORD_CHOSEN_BY_THE_SAM;

import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keypop.calypso.crypto.legacysam.SystemKeyType;
import org.eclipse.keypop.card.ApduResponseApi;

/**
 * Builds the Write Key APDU command.
 *
 * @since 0.9.0
 */
final class CommandWriteKey extends Command {

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
        new StatusProperties(
            "Preconditions not satisfied:\n"
                + "- The SAM is locked.\n"
                + "- Lock secret and LockedLock=1 at last reset.\n"
                + "- CipherEnableBit of PAR1 is 0.\n"
                + "- Dynamic mode ciphering and the outgoing challenge is unavailable.\n"
                + "- System key and SystemLockEnableBit=1.\n"
                + "- Work key and WorkKeysLockEnableBit=1.\n"
                + "- Work key and no empty record in the Work Key File.\n"
                + "- Plain lock secret loading and PlainWriteDisabled=1 at last reset.\n"
                + "- Plain work key loading and PlainWorkKeyInputEnableBit=0.\n"
                + "- Work key loading by record number reference and record is not empty.\n"
                + "- Static mode and StaticCipherEnableBit=0",
            AccessForbiddenException.class));
    m.put(0x6988, new StatusProperties("Incorrect signature", SecurityDataException.class));
    m.put(
        0x6A00,
        new StatusProperties(
            "P1 or P2 incorrect:\n"
                + "- Incorrect data reference (P2≠01h to 7Eh, C0h, E0h and F0h).\n"
                + "- Ciphered data and random value (P1=%01xxxxxx).\n"
                + "- System key and plain data (P1=%1xxxxxxx and P2=C0h).\n"
                + "- Random value for system or lock secret (P2=C0h or E0h and P1=%x1xxxxxx).",
            IllegalParameterException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Incorrect plain or decrypted data:\n"
                + "- P2 different from P2 in command header.\n"
                + "- Ciphered mode and incorrect decrypted data.\n"
                + "- Received parameters incorrect (unknown ALG).\n"
                + "- Incorrect KIF for a system key (KIF≠%1xxxxxxx).\n"
                + "- Incorrect KIF for the lock secret (KIF≠EFh).\n"
                + "- Ciphered system or work key writing: PAR7 to PAR10 bytes not all null.\n"
                + "- Work key already exists.\n"
                + "- Work key, given KIF=E1h or FDh, and SystemLockEnableBit =1.\n"
                + "- CAAD Transfer Control data present and PAR6≤80h or >87h.\n"
                + "- CAAD Transfer Control data do not match CAAD record indicated by PAR6–80h",
            IncorrectInputDataException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found:\n"
                + "- Deciphering key not found.\n"
                + "- CAAD Transfer Control data present and target CAAD record empty",
            DataAccessException.class));
    m.put(
        0x6A87,
        new StatusProperties(
            "Lc inconsistent with P1 or P2:\n"
                + "- Plain data and CAAD Transfer Control data present (Lc=50h).\n"
                + "- Not a work key and CAAD Transfer Control data present (Lc=50h).",
            IncorrectInputDataException.class));
    STATUS_TABLE = m;
  }

  private final byte targetKeyReference;
  private final SystemKeyType cipheringKeyType;
  private final byte sourceKeyKif;
  private final byte sourceKeyKvc;
  private final byte[] keyParameters;
  private final boolean isTransferredObjectDiversified;

  private byte cipheringKeyKvc;
  private byte[] writeKeyCommandData; // either ciphered or plain data block
  private byte[] arbitraryDiversifier;

  /**
   * Constructor
   *
   * @param context The command context.
   * @param systemKeyType The type of the system key to transfer.
   * @param kvc The KVC of the key to transfer.
   * @param keyParameters The key parameters.
   * @param isTransferredKeyDiversified true if the transferred key needs to be diversified.
   * @since 0.9.0
   */
  CommandWriteKey(
      CommandContextDto context,
      SystemKeyType systemKeyType,
      byte kvc,
      byte[] keyParameters,
      boolean isTransferredKeyDiversified) {

    super(CommandRef.WRITE_KEY, 0, context);

    cipheringKeyType = SystemKeyType.PERSONALIZATION;
    targetKeyReference = LegacySamConstants.TARGET_IS_SYSTEM_KEY_FILE;
    sourceKeyKif = LegacySamConstants.SystemKeyTypeKifMapper.getKif(systemKeyType);
    sourceKeyKvc = kvc;
    this.keyParameters = keyParameters;
    isTransferredObjectDiversified = isTransferredKeyDiversified;
  }

  /**
   * Constructor
   *
   * @param context The command context.
   * @param kif The KIF of the key to transfer.
   * @param kvc The KVC of the key to transfer.
   * @param targetRecordNumber The number of the record where to write the key.
   * @param keyParameters The key parameters.
   * @param isTransferredKeyDiversified true if the transferred key needs to be diversified.
   * @since 0.9.0
   */
  CommandWriteKey(
      CommandContextDto context,
      byte kif,
      byte kvc,
      int targetRecordNumber,
      byte[] keyParameters,
      boolean isTransferredKeyDiversified) {

    super(CommandRef.WRITE_KEY, 0, context);

    cipheringKeyType = SystemKeyType.KEY_MANAGEMENT;
    targetKeyReference =
        targetRecordNumber == 0 ? RECORD_CHOSEN_BY_THE_SAM : (byte) targetRecordNumber;
    sourceKeyKif = kif;
    sourceKeyKvc = kvc;
    this.keyParameters = keyParameters;
    isTransferredObjectDiversified = isTransferredKeyDiversified;
  }

  /**
   * Constructor
   *
   * @param context The command context.
   * @param kif The KIF of the key to transfer.
   * @param kvc The KVC of the key to transfer.
   * @param targetRecordNumber The number of the record where to write the key.
   * @param keyParameters The key parameters.
   * @param diversifier The diversifier to use as ArbitraryDiversifier.
   * @since 0.9.0
   */
  public CommandWriteKey(
      CommandContextDto context,
      byte kif,
      byte kvc,
      int targetRecordNumber,
      byte[] keyParameters,
      byte[] diversifier) {

    super(CommandRef.WRITE_KEY, 0, context);

    cipheringKeyType = SystemKeyType.KEY_MANAGEMENT;
    targetKeyReference =
        targetRecordNumber == 0 ? RECORD_CHOSEN_BY_THE_SAM : (byte) targetRecordNumber;
    sourceKeyKif = kif;
    sourceKeyKvc = kvc;
    this.keyParameters = keyParameters;
    isTransferredObjectDiversified = true;
    this.arbitraryDiversifier = diversifier;
  }

  /**
   * Constructor
   *
   * @param context The command context.
   * @param lockIndex The index of the lock file.
   * @param lockParameters The lock permissions parameters.
   * @since 0.9.0
   */
  public CommandWriteKey(
      CommandContextDto context,
      byte lockIndex,
      byte lockParameters,
      boolean isTransferredLockDiversified) {
    super(CommandRef.WRITE_KEY, 0, context);

    cipheringKeyType = SystemKeyType.PERSONALIZATION;
    targetKeyReference = LegacySamConstants.TARGET_IS_LOCK_FILE;
    sourceKeyKif = LegacySamConstants.LOCK_KIF;
    sourceKeyKvc = lockIndex;
    byte[] lockParametersAsKeyParameters = new byte[LegacySamConstants.KEY_PARAMETERS_LENGTH];
    lockParametersAsKeyParameters[5] = lockParameters;
    this.keyParameters = lockParametersAsKeyParameters;
    isTransferredObjectDiversified = isTransferredLockDiversified;
  }

  /**
   * Constructor
   *
   * @param context The command context.
   * @param plainLockDataBlock A 48-byte byte array representing the lock data block including the
   *     lock file.
   * @since 0.9.0
   */
  public CommandWriteKey(CommandContextDto context, byte[] plainLockDataBlock) {
    super(CommandRef.WRITE_KEY, 0, context);
    writeKeyCommandData = plainLockDataBlock;
    // initialize unused final fields
    cipheringKeyType = null;
    targetKeyReference = LegacySamConstants.TARGET_IS_LOCK_FILE;
    cipheringKeyKvc = 0;
    sourceKeyKif = 0;
    sourceKeyKvc = 0;
    keyParameters = new byte[0];
    isTransferredObjectDiversified = false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  void finalizeRequest() {
    byte p1;
    if (writeKeyCommandData == null) {
      cipheringKeyKvc =
          getContext().getTargetSam().getSystemKeyParameter(cipheringKeyType).getKvc();
      // it is a key transfer
      CommandContextDto controlSamContext =
          new CommandContextDto(getContext().getControlSam(), null, null);
      byte[] diversifier = new byte[8];
      System.arraycopy(getContext().getTargetSam().getSerialNumber(), 0, diversifier, 4, 4);
      addControlSamCommand(new CommandSelectDiversifier(controlSamContext, diversifier));
      addControlSamCommand(
          new CommandGiveRandom(controlSamContext, getContext().getTargetSam().popChallenge()));
      CommandSamGenerateKey commandSamGenerateKey =
          new CommandSamGenerateKey(
              controlSamContext,
              targetKeyReference,
              cipheringKeyKvc,
              sourceKeyKif,
              sourceKeyKvc,
              keyParameters,
              isTransferredObjectDiversified,
              arbitraryDiversifier);
      addControlSamCommand(commandSamGenerateKey);
      processControlSamCommand();
      writeKeyCommandData = commandSamGenerateKey.getCipheredData();
      p1 = 0x00; // ciphered data mode
    } else {
      p1 = (byte) (0x80); // plain data mode
    }

    final byte cla = getContext().getTargetSam().getClassByte();
    final byte ins = CommandRef.WRITE_KEY.getInstructionByte();
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, ins, p1, targetKeyReference, writeKeyCommandData, null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  boolean isControlSamRequiredToFinalizeRequest() {
    return true;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  void parseResponse(ApduResponseApi apduResponse) throws CommandException {
    setResponseAndCheckStatus(apduResponse);
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
