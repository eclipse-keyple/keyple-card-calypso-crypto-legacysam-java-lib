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

import java.util.EnumMap;
import java.util.Map;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.crypto.legacysam.SystemKeyType;

/**
 * Constants related to Calypso cards.
 *
 * @since 2.0.0
 */
final class LegacySamConstants {

  private LegacySamConstants() {}

  static final int MIN_KEY_RECORD_NUMBER = 1;
  static final int MAX_KEY_RECORD_NUMBER = 126;
  static final int MIN_COUNTER_NUMBER = 0;
  static final int MAX_COUNTER_NUMBER = 26;
  static final int MIN_COUNTER_CEILING_NUMBER = 0;
  static final int MAX_COUNTER_CEILING_NUMBER = 26;
  static final int MIN_COUNTER_CEILING_VALUE = 0;
  static final int MAX_COUNTER_CEILING_VALUE = 0xFFFFFA;
  static final int[] COUNTER_TO_RECORD_LOOKUP = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2
  };
  static final byte AID_SIZE_MAX = 16;
  static final int CA_CERTIFICATE_SIZE = 384;
  static final int ECC_PUBLIC_KEY_SIZE = 64;
  static final int PLAIN_CEILING_DATA_BLOCK_SIZE = 30;
  static final int KEY_DATA_BLOCK_SIZE = 48;
  static final int LOCK_FILE_SIZE = 29;
  static final int SAM_PARAMETERS_LENGTH = 29;
  static final int KEY_PARAMETERS_LENGTH = 10;
  static final int LOCK_VALUE_LENGTH = 16;

  static final byte TARGET_IS_SYSTEM_KEY_FILE = (byte) 0xC0;
  static final byte TARGET_IS_LOCK_FILE = (byte) 0xE0;

  static final byte FIRST_EVENT_CEILING_RECORD_REFERENCE = (byte) 0xB1;
  static final byte SINGLE_CEILING_REFERENCE = (byte) 0xB8;

  static final byte LOCK_KIF = (byte) 0xEF;

  static final byte DYNAMIC_MODE_CIPHERING = (byte) 0x00;
  static final byte STATIC_MODE_CIPHERING = (byte) 0x08;

  /** Mapper for SystemKeyType to kif values. */
  static class SystemKeyTypeKifMapper {
    private static final Map<SystemKeyType, Byte> kifMap = new EnumMap<>(SystemKeyType.class);

    private SystemKeyTypeKifMapper() {}

    static {
      kifMap.put(SystemKeyType.PERSONALIZATION, (byte) 0xE1);
      kifMap.put(SystemKeyType.KEY_MANAGEMENT, (byte) 0xFD);
      kifMap.put(SystemKeyType.RELOADING, (byte) 0xE7);
      kifMap.put(SystemKeyType.AUTHENTICATION, (byte) 0xFA);
    }

    public static byte getKif(SystemKeyType keyType) {
      return kifMap.get(keyType);
    }
  }

  /**
   * Enum representing the different tags used in Get Data APDU command and providing precomputed
   * values.
   *
   * @since 0.6.0
   */
  enum TagInfo {
    CA_CERTIFICATE(0xDF43, CA_CERTIFICATE_SIZE, HexUtil.toByteArray("DF43820180")),
    CARD_PUBLIC_KEY_DATA(0xDF25, 60, HexUtil.toByteArray("DF253F")),
    GENERATED_CARD_ECC_KEY_PAIR(0xDF3C, 96, HexUtil.toByteArray("DF3C60")),
    GENERATED_CARD_CERTIFICATE(0xDF45, 316, HexUtil.toByteArray("DF4582013C"));

    private final int value;
    private final int length;
    private final int totalLength;
    private final byte[] header;
    private final byte lsb;
    private final byte msb;

    /** Constructor. */
    TagInfo(int value, int length, byte[] header) {
      this.value = value;
      this.length = length;
      this.header = header;
      this.lsb = (byte) (value & 0xFF);
      this.msb = (byte) ((value & 0xFF00) >> 8);
      this.totalLength = length + header.length;
    }

    int getValue() {
      return value;
    }

    int getLength() {
      return length;
    }

    int getTotalLength() {
      return totalLength;
    }

    byte[] getHeader() {
      return header;
    }

    byte getLsb() {
      return lsb;
    }

    byte getMsb() {
      return msb;
    }
  }
}
