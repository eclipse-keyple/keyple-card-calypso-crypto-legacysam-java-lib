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

import static org.eclipse.keyple.card.calypso.crypto.legacysam.DtoAdapters.*;

import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.card.ApduResponseApi;

/**
 * Superclass for all SAM commands.
 *
 * <p>It provides the generic getters to retrieve:
 *
 * <ul>
 *   <li>the card command reference,
 *   <li>the name of the command,
 *   <li>the built {@link org.calypsonet.terminal.card.spi.ApduRequestSpi},
 *   <li>the parsed {@link ApduResponseApi}.
 * </ul>
 *
 * @since 0.1.0
 */
abstract class Command {

  /**
   * This Map stores expected status that could be by default initialized with sw1=90 and sw2=00
   * (Success)
   *
   * @since 0.1.0
   */
  static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    HashMap<Integer, StatusProperties> m = new HashMap<Integer, StatusProperties>();
    m.put(0x6D00, new StatusProperties("Instruction unknown.", IllegalParameterException.class));
    m.put(0x6E00, new StatusProperties("Class not supported.", IllegalParameterException.class));
    m.put(0x9000, new StatusProperties("Success"));
    STATUS_TABLE = m;
  }

  private final CommandRef commandRef;
  private final int le;
  private String name;
  private ApduRequestAdapter apduRequest;
  private ApduResponseApi apduResponse;
  private LegacySamAdapter legacySam;

  /**
   * Constructor dedicated for the building of referenced Calypso commands
   *
   * @param commandRef A command reference from the Calypso command table.
   * @param le The value of the LE field.
   * @param legacySam The Calypso legacy SAM (it may be null if the SAM selection has not yet been
   *     made).
   * @since 0.1.0
   */
  Command(CommandRef commandRef, int le, LegacySamAdapter legacySam) {
    this.commandRef = commandRef;
    this.name = commandRef.getName();
    this.le = le;
    this.legacySam = legacySam;
  }

  /**
   * Appends a string to the current name.
   *
   * <p>The sub name completes the name of the current command. This method must therefore only be
   * invoked conditionally (log level &gt;= debug).
   *
   * @param subName The string to append.
   * @throws NullPointerException If the request is not set.
   * @since 0.1.0
   */
  final void addSubName(String subName) {
    this.name = this.name + " - " + subName;
    this.apduRequest.setInfo(this.name);
  }

  /**
   * Returns the current command identification
   *
   * @return A not null reference.
   * @since 0.1.0
   */
  final CommandRef getCommandRef() {
    return commandRef;
  }

  /**
   * Gets the name of this APDU command.
   *
   * @return A not empty string.
   * @since 0.1.0
   */
  final String getName() {
    return this.name;
  }

  /**
   * Sets the command {@link ApduRequestAdapter}.
   *
   * @param apduRequest The APDU request.
   * @since 0.1.0
   */
  final void setApduRequest(ApduRequestAdapter apduRequest) {
    this.apduRequest = apduRequest;
    this.apduRequest.setInfo(this.name);
  }

  /**
   * Gets the {@link ApduRequestAdapter}.
   *
   * @return Null if the request is not set.
   * @since 0.1.0
   */
  final ApduRequestAdapter getApduRequest() {
    return apduRequest;
  }

  /**
   * Gets {@link ApduResponseApi}
   *
   * @return Null if the response is not set.
   * @since 0.1.0
   */
  final ApduResponseApi getApduResponse() {
    return apduResponse;
  }

  /**
   * Returns the Calypso card.
   *
   * @return Null if the SAM selection has not yet been made.
   * @since 0.1.0
   */
  final LegacySamAdapter getLegacySam() {
    return legacySam;
  }

  /**
   * Parses the response {@link ApduResponseApi} and checks the status word.
   *
   * @param apduResponse The APDU response.
   * @throws CommandException if status is not successful or if the length of the response is not
   *     equal to the LE field in the request.
   * @since 0.1.0
   */
  void parseApduResponse(ApduResponseApi apduResponse) throws CommandException {
    this.apduResponse = apduResponse;
    checkStatus();
  }

  /**
   * Returns the internal status table
   *
   * @return A not null reference
   * @since 0.1.0
   */
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }

  /**
   * @return The properties of the result.
   * @throws NullPointerException If the response is not set.
   */
  private StatusProperties getStatusWordProperties() {
    return getStatusTable().get(apduResponse.getStatusWord());
  }

  /**
   * Gets true if the status is successful from the statusTable according to the current status code
   * and if the length of the response is equal to the LE field in the request.
   *
   * @return A value
   * @since 0.1.0
   */
  final boolean isSuccessful() {
    StatusProperties props = getStatusWordProperties();
    return props != null
        && props.isSuccessful()
        && (le == 0 || apduResponse.getDataOut().length == le); // CL-CSS-RESPLE.1
  }

  /**
   * This method check the status word and if the length of the response is equal to the LE field in
   * the request.<br>
   * If status word is not referenced, then status is considered unsuccessful.
   *
   * @throws CommandException if status is not successful or if the length of the response is not
   *     equal to the LE field in the request.
   */
  private void checkStatus() throws CommandException {

    StatusProperties props = getStatusWordProperties();
    if (props != null && props.isSuccessful()) {
      // SW is successful, then check the response length (CL-CSS-RESPLE.1)
      if (le != 0 && apduResponse.getDataOut().length != le) {
        throw new UnexpectedResponseLengthException(
            String.format(
                "Incorrect APDU response length (expected: %d, actual: %d)",
                le, apduResponse.getDataOut().length));
      }
      // SW and response length are correct.
      return;
    }
    // status word is not referenced, or not successful.

    // exception class
    Class<? extends CommandException> exceptionClass =
        props != null ? props.getExceptionClass() : null;

    // message
    String message = props != null ? props.getInformation() : "Unknown status";

    // Throw the exception
    throw buildCommandException(exceptionClass, message);
  }

  /**
   * Gets the ASCII message from the statusTable for the current status word.
   *
   * @return A nullable value
   * @since 0.1.0
   */
  final String getStatusInformation() {
    StatusProperties props = getStatusWordProperties();
    return props != null ? props.getInformation() : null;
  }

  /**
   * Builds a specific APDU command exception.
   *
   * @param exceptionClass the exception class.
   * @param message The message.
   * @return A not null reference.
   * @since 0.1.0
   */
  CommandException buildCommandException(
      Class<? extends CommandException> exceptionClass, String message) {
    CommandException e;
    if (exceptionClass == AccessForbiddenException.class) {
      e = new AccessForbiddenException(message);
    } else if (exceptionClass == CounterOverflowException.class) {
      e = new CounterOverflowException(message);
    } else if (exceptionClass == DataAccessException.class) {
      e = new DataAccessException(message);
    } else if (exceptionClass == IllegalParameterException.class) {
      e = new IllegalParameterException(message);
    } else if (exceptionClass == IncorrectInputDataException.class) {
      e = new IncorrectInputDataException(message);
    } else if (exceptionClass == SecurityDataException.class) {
      e = new SecurityDataException(message);
    } else if (exceptionClass == SecurityContextException.class) {
      e = new SecurityContextException(message);
    } else {
      e = new UnknownStatusException(message);
    }
    return e;
  }

  /**
   * This internal class provides status word properties
   *
   * @since 0.1.0
   */
  static class StatusProperties {

    private final String information;

    private final boolean successful;

    private final Class<? extends CommandException> exceptionClass;

    /**
     * Creates a successful status.
     *
     * @param information the status information.
     * @since 0.1.0
     */
    StatusProperties(String information) {
      this.information = information;
      this.successful = true;
      this.exceptionClass = null;
    }

    /**
     * Creates an error status.<br>
     * If {@code exceptionClass} is null, then a successful status is created.
     *
     * @param information the status information.
     * @param exceptionClass the associated exception class.
     * @since 0.1.0
     */
    StatusProperties(String information, Class<? extends CommandException> exceptionClass) {
      this.information = information;
      this.successful = exceptionClass == null;
      this.exceptionClass = exceptionClass;
    }

    /**
     * Gets information
     *
     * @return A nullable reference
     * @since 0.1.0
     */
    String getInformation() {
      return information;
    }

    /**
     * Gets successful indicator
     *
     * @return The successful indicator
     * @since 0.1.0
     */
    boolean isSuccessful() {
      return successful;
    }

    /**
     * Gets Exception Class
     *
     * @return A nullable reference
     * @since 0.1.0
     */
    Class<? extends CommandException> getExceptionClass() {
      return exceptionClass;
    }
  }
}
