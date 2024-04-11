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

import org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySam;

/**
 * Util to help with Legacy SAM specificities.
 *
 * @since 0.4.0
 */
public final class LegacySamUtil {

  /** Private constructor */
  private LegacySamUtil() {}

  /**
   * Create a regular expression to be used as "Power on data" filter in the selection process.
   *
   * <p>Two criteria are available:
   *
   * <ul>
   *   <li>A filter to target SAMs having a specific {@link LegacySam.ProductType}.
   *   <li>A filter to target SAMs having a serial number matching a specific regular expression.
   * </ul>
   *
   * <p>Concerning the serial number, the regular expression is based on a hexadecimal
   * representation of the number.
   *
   * <p>Example:
   *
   * <ul>
   *   <li>A filter targeting all SAMs having an 8-byte serial number starting with A0h would be
   *       "^A0.{6}$".
   *   <li>A filter targeting a SAM having the exact serial number 12345678h would be "12345678".
   * </ul>
   *
   * <p>Both argument are optional and can be null.
   *
   * @param productType The target SAM product type.
   * @param serialNumberRegex A regular expression matching the SAM serial number.
   * @return A not empty string containing a regular
   * @throws IllegalArgumentException If productType is null.
   * @throws IllegalArgumentException If serialNumberRegex is null, empty or invalid.
   * @since 0.4.0
   */
  public static String buildPowerOnDataFilter(
      LegacySam.ProductType productType, String serialNumberRegex) {
    String atrRegex;
    String snRegex;
    /* check if serialNumber is defined */
    if (serialNumberRegex == null || serialNumberRegex.isEmpty()) {
      /* match all serial numbers */
      snRegex = ".{8}";
    } else {
      /* match the provided serial number (could be a regex substring) */
      snRegex = serialNumberRegex;
    }
    /*
     * build the final Atr regex according to the SAM subtype and serial number if any.
     *
     * The header is starting with 3B, its total length is 4 or 6 bytes (8 or 10 hex digits)
     */
    String applicationTypeMask;
    if (productType != null) {
      switch (productType) {
        case SAM_C1:
        case HSM_C1:
          applicationTypeMask = "C1";
          break;
        case SAM_S1DX:
          applicationTypeMask = "D?";
          break;
        case SAM_S1E1:
          applicationTypeMask = "E1";
          break;
        default:
          throw new IllegalArgumentException("Unknown SAM subtype.");
      }
      atrRegex = "3B(.{6}|.{10})805A..80" + applicationTypeMask + ".{6}" + snRegex + "829000";
    } else {
      /* match any ATR */
      atrRegex = ".*";
    }
    return atrRegex;
  }

  /**
   * Converts the provided date into a long. It is in BCD format 0xYYYYMMDD, where YYYY represents
   * the four-digit year, MM the two-digit month, and DD the two-digit day.
   *
   * @param year The year (0-9999).
   * @param month The month (1-99).
   * @param day The day (1-99).
   * @return A long in BCD format.
   * @since 0.6.0
   */
  static long convertDateToBcdLong(int year, int month, int day) {
    long bcdYear =
        ((long) (year / 1000) << 12)
            | ((year / 100 % 10) << 8)
            | ((year % 100 / 10) << 4)
            | (year % 10);
    long bcdMonth = ((long) (month / 10) << 4) | (month % 10);
    long bcdDay = ((long) (day / 10) << 4) | (day % 10);
    return (bcdYear << 16) | (bcdMonth << 8) | bcdDay;
  }
}
