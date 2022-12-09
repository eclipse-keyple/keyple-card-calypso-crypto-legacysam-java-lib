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

import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * Builds the Read Key Parameters APDU command.
 *
 * @since 0.1.0
 */
final class CommandReadKeyParameters extends Command {

  /** The command reference. */
  private static final CommandRef commandRef = CommandRef.READ_KEY_PARAMETERS;

  private static final int MAX_WORK_KEY_REC_NUMB = 126;

  /** Source reference */
  enum SourceRef {
    /** Work key */
    WORK_KEY,
    /** System key */
    SYSTEM_KEY
  }

  /** Navigation control */
  enum NavControl {
    /** First */
    FIRST,
    /** Next */
    NEXT
  }

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<Integer, StatusProperties>(Command.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", IllegalParameterException.class));
    m.put(
        0x6900,
        new StatusProperties(
            "An event counter cannot be incremented.", CounterOverflowException.class));
    m.put(0x6A00, new StatusProperties("Incorrect P2.", IllegalParameterException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found: key to read not found.", DataAccessException.class));
    m.put(0x6200, new StatusProperties("Correct execution with warning: data not signed.", null));
    STATUS_TABLE = m;
  }

  /**
   * Instantiates a new CmdSamReadKeyParameters for the null key.
   *
   * @param legacySam The Calypso legacy SAM.
   * @since 0.1.0
   */
  CommandReadKeyParameters(LegacySamAdapter legacySam) {

    super(commandRef, 0, legacySam);

    byte cla = legacySam.getClassByte();

    byte p2 = (byte) 0xE0;
    byte[] sourceKeyId = new byte[] {0x00, 0x00};

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cla, commandRef.getInstructionByte(), (byte) 0x00, p2, sourceKeyId, (byte) 0x00)));
  }

  /**
   * Instantiates a new CmdSamReadKeyParameters for the provided kif.
   *
   * @param legacySam The Calypso legacy SAM.
   * @param kif the kif
   * @since 0.1.0
   */
  CommandReadKeyParameters(LegacySamAdapter legacySam, byte kif) {

    super(commandRef, 0, legacySam);

    byte cla = legacySam.getClassByte();

    byte p2 = (byte) 0xC0;
    byte[] sourceKeyId = new byte[] {0x00, 0x00};

    sourceKeyId[0] = kif;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cla, commandRef.getInstructionByte(), (byte) 0x00, p2, sourceKeyId, (byte) 0x00)));
  }

  /**
   * Instantiates a new CmdSamReadKeyParameters for the provided kif and kvc.
   *
   * @param legacySam The Calypso legacy SAM.
   * @param kif the kif
   * @param kvc the kvc
   * @since 0.1.0
   */
  CommandReadKeyParameters(LegacySamAdapter legacySam, byte kif, byte kvc) {

    super(commandRef, 0, legacySam);

    byte cla = legacySam.getClassByte();

    byte p2 = (byte) 0xF0;
    byte[] sourceKeyId = new byte[] {0x00, 0x00};

    sourceKeyId[0] = kif;
    sourceKeyId[1] = kvc;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cla, commandRef.getInstructionByte(), (byte) 0x00, p2, sourceKeyId, (byte) 0x00)));
  }

  /**
   * Instantiates a new CmdSamReadKeyParameters for the provided key reference and record number.
   *
   * @param legacySam The Calypso legacy SAM.
   * @param sourceKeyRef the source key reference
   * @param recordNumber the record number
   * @since 0.1.0
   */
  CommandReadKeyParameters(LegacySamAdapter legacySam, SourceRef sourceKeyRef, int recordNumber) {

    super(commandRef, 0, legacySam);

    if (recordNumber < 1 || recordNumber > MAX_WORK_KEY_REC_NUMB) {
      throw new IllegalArgumentException(
          "Record Number must be between 1 and " + MAX_WORK_KEY_REC_NUMB + ".");
    }

    byte cla = legacySam.getClassByte();

    byte p2;
    byte[] sourceKeyId = new byte[] {0x00, 0x00};

    switch (sourceKeyRef) {
      case WORK_KEY:
        p2 = (byte) recordNumber;
        break;

      case SYSTEM_KEY:
        p2 = (byte) (0xC0 + (byte) recordNumber);
        break;

      default:
        throw new IllegalStateException("Unsupported SourceRef parameter " + sourceKeyRef);
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cla, commandRef.getInstructionByte(), (byte) 0x00, p2, sourceKeyId, (byte) 0x00)));
  }

  /**
   * Instantiates a new CmdSamReadKeyParameters for the provided kif and navigation control flag.
   *
   * @param legacySam The Calypso legacy SAM.
   * @param kif the kif
   * @param navControl the navigation control flag
   * @since 0.1.0
   */
  CommandReadKeyParameters(LegacySamAdapter legacySam, byte kif, NavControl navControl) {

    super(commandRef, 0, legacySam);

    byte cla = legacySam.getClassByte();

    byte p2;
    byte[] sourceKeyId = new byte[] {0x00, 0x00};

    switch (navControl) {
      case FIRST:
        p2 = (byte) 0xF8;
        break;

      case NEXT:
        p2 = (byte) 0xFA;
        break;

      default:
        throw new IllegalStateException("Unsupported NavControl parameter " + navControl);
    }

    sourceKeyId[0] = kif;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cla, commandRef.getInstructionByte(), (byte) 0x00, p2, sourceKeyId, (byte) 0x00)));
  }

  /**
   * Gets the key parameters.
   *
   * @return The key parameters
   * @since 0.1.0
   */
  byte[] getKeyParameters() {
    return isSuccessful() ? getApduResponse().getDataOut() : null;
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
}
