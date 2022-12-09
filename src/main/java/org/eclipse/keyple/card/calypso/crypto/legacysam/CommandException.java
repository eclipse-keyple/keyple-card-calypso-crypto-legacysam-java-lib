/* **************************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://calypsonet.org/
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
 * Parent abstract class of all Keyple SAM APDU commands exceptions.
 *
 * @since 0.1.0
 */
abstract class CommandException extends Exception {

  /**
   * @param message the message to identify the exception context.
   * @since 0.1.0
   */
  CommandException(String message) {
    super(message);
  }
}
