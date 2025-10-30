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

/**
 * Contains additional parameters for the management of context specific cases.
 *
 * @since 0.4.0
 */
public interface ContextSetting {

  /**
   * Defines the maximum size of APDUs payload (**Lc** field value) that the library can generate
   * when communicating with a contact card.
   *
   * <p>As an example, here are the values to be set for communication with the SAM when used in HSP
   * mode:
   *
   * <ul>
   *   <li>SAM-C1 in HSP mode, set {@code payloadCapacity} to 248.
   *   <li>SAM-E1 in HSP mode, set {@code payloadCapacity} to 239.
   * </ul>
   *
   * @param payloadCapacity A positive integer lower than 255.
   * @return The current instance.
   * @throws IllegalArgumentException If payloadCapacity is out of range.
   * @since 0.4.0
   */
  ContextSetting setContactReaderPayloadCapacity(int payloadCapacity);
}
