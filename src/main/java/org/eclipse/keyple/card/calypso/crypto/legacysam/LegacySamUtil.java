package org.eclipse.keyple.card.calypso.crypto.legacysam;

import org.calypsonet.terminal.calypso.crypto.legacysam.sam.LegacySam;

public final class LegacySamUtil {

  private LegacySamUtil() {}

  /**
   *
   * @param productType
   * @param serialNumberRegex
   * @return
   */
  public static String buildPowerOnDataFilter (LegacySam.ProductType productType, String serialNumberRegex) {
    // TODO
    return null;
  }

  /**
   * Sets a filter to target SAMs having a specific {@link LegacySam.ProductType}.
   *
   * @param productType The SAM product type.
   * @return The current instance.
   * @throws IllegalArgumentException If the provided argument is null.
   * @since 0.1.0
   */

  /**
   * Sets a filter to target SAMs having a serial number matching a specific regular expression.
   *
   * <p>The regular expression is based on a hexadecimal representation of the serial number.
   *
   * <p>Example:
   *
   * <ul>
   *   <li>A filter targeting all SAMs having an 8-byte serial number starting with A0h would be
   *       "^A0.{6}$".
   *   <li>A filter targeting a SAM having the exact serial number 12345678h would be "12345678".
   * </ul>
   *
   * @param serialNumberRegex A regular expression.
   * @return The current instance.
   * @throws IllegalArgumentException If the provided regex is null, empty or invalid.
   * @since 0.1.0
   */
}
