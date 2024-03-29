/* **************************************************************************************
 * Copyright (c) 2018 Calypso Networks Association https://calypsonet.org/
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

/**
 * Defines all supported Calypso legacy SAM APDU commands.
 *
 * @since 0.1.0
 */
enum CommandRef {
  SELECT_DIVERSIFIER("Select Diversifier", (byte) 0x14),
  GET_CHALLENGE("Get Challenge", (byte) 0x84),
  DIGEST_INIT("Digest Init", (byte) 0x8A),
  DIGEST_UPDATE("Digest Update", (byte) 0x8C),
  DIGEST_UPDATE_MULTIPLE("Digest Update Multiple", (byte) 0x8C),
  DIGEST_CLOSE("Digest Close", (byte) 0x8E),
  DIGEST_AUTHENTICATE("Digest Authenticate", (byte) 0x82),
  DIGEST_INTERNAL_AUTHENTICATE("Digest Internal Authenticate", (byte) 0x88),
  GIVE_RANDOM("Give Random", (byte) 0x86),
  CARD_GENERATE_KEY("Card Generate Key", (byte) 0x12),
  CARD_CIPHER_PIN("Card Cipher PIN", (byte) 0x12),
  UNLOCK("Unlock", (byte) 0x20),
  WRITE_KEY("Write Key", (byte) 0x1A),
  READ_KEY_PARAMETERS("Read Key Parameters", (byte) 0xBC),
  READ_COUNTER("Read Event Counter", (byte) 0xBE),
  READ_CEILINGS("Read Ceilings", (byte) 0xBE),
  SV_CHECK("SV Check", (byte) 0x58),
  SV_PREPARE_DEBIT("SV Prepare Debit", (byte) 0x54),
  SV_PREPARE_LOAD("SV Prepare Load", (byte) 0x56),
  SV_PREPARE_UNDEBIT("SV Prepare Undebit", (byte) 0x5C),
  DATA_CIPHER("Data Cipher", (byte) 0x1C),
  PSO_COMPUTE_SIGNATURE("PSO Compute Signature", (byte) 0x2A),
  PSO_VERIFY_SIGNATURE("PSO Verify Signature", (byte) 0x2A),
  SAM_DATA_CIPHER("SAM Data Cipher", (byte) 0x16),
  WRITE_CEILINGS("Write Ceilings", (byte) 0xD8),
  GET_DATA("Get Data", (byte) 0xCA),
  PSO_COMPUTE_CERTIFICATE("PSO Compute Certificate", (byte) 0x2A),
  CARD_GENERATE_ASYMMETRIC_KEY_PAIR("Card Generate Asymmetric Key Pair", (byte) 0x46);
  /** The name. */
  private final String name;

  /** The instruction byte. */
  private final byte instructionByte;

  /**
   * The generic constructor of CalypsoCommands.
   *
   * @param name the name.
   * @param instructionByte the instruction byte.
   * @since 0.1.0
   */
  CommandRef(String name, byte instructionByte) {
    this.name = name;
    this.instructionByte = instructionByte;
  }

  /**
   * Gets the name.
   *
   * @return A String
   * @since 0.1.0
   */
  public String getName() {
    return name;
  }

  /**
   * Gets the instruction byte (INS).
   *
   * @return A byte
   * @since 0.1.0
   */
  public byte getInstructionByte() {
    return instructionByte;
  }
}
