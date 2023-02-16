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

import static org.eclipse.keyple.card.calypso.crypto.legacysam.DtoAdapters.*;

import java.util.ArrayList;
import java.util.List;
import org.calypsonet.terminal.card.*;

/**
 * Abstract class of all transaction manager adapters.
 *
 * @since 0.3.0
 */
abstract class CommonTransactionManagerAdapter {
  /* Constants */
  static final int MIN_COUNTER_NUMBER = 0;
  static final int MAX_COUNTER_NUMBER = 26;
  static final int MIN_COUNTER_CEILING_NUMBER = 0;
  static final int MAX_COUNTER_CEILING_NUMBER = 26;
  static final int MIN_COUNTER_CEILING_VALUE = 0;
  static final int MAX_COUNTER_CEILING_VALUE = 0xFFFFFA;
  static final int NB_COUNTER_CEILING_PER_RECORD = 9;
  static final int FIRST_COUNTER_REC1 = 0;
  static final int LAST_COUNTER_REC1 = 8;
  static final int FIRST_COUNTER_REC2 = 9;
  static final int LAST_COUNTER_REC2 = 17;
  static final int FIRST_COUNTER_REC3 = 18;
  static final int LAST_COUNTER_REC3 = 26;
  /* JSON field names */
  static final String SAM_COMMANDS_TYPES = "samCommandsTypes";
  static final String SAM_COMMANDS = "samCommands";

  static final int[] counterToRecordLookup =
      new int[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2};
  private final ProxyReaderApi targetSamReader;
  private final LegacySamAdapter targetSam;
  private final ProxyReaderApi controlSamReader;
  private final LegacySamAdapter controlSam;
  private final List<Command> targetSamCommands = new ArrayList<Command>();

  /**
   * Constructor
   *
   * @param targetSamReader The reader through which the target SAM communicates.
   * @param targetSam The target legacy SAM.
   * @param controlSamReader The reader through which the control SAM communicates.
   * @param controlSam The control legacy SAM.
   */
  CommonTransactionManagerAdapter(
      ProxyReaderApi targetSamReader,
      LegacySamAdapter targetSam,
      ProxyReaderApi controlSamReader,
      LegacySamAdapter controlSam) {
    this.targetSamReader = targetSamReader;
    this.targetSam = targetSam;
    this.controlSamReader = controlSamReader;
    this.controlSam = controlSam;
  }

  /**
   * Gets the target SAM reader.
   *
   * @return Null if no target SAM reader is set.
   * @since 0.3.0
   */
  final ProxyReaderApi getTargetSamReader() {
    return targetSamReader;
  }

  /**
   * Gets the command context.
   *
   * @return An instance of {@link CommandContextDto}.
   * @since 0.3.0
   */
  final CommandContextDto getContext() {
    return new CommandContextDto(targetSam, controlSamReader, controlSam);
  }

  /**
   * Adds a command to be executed be the target SAM.
   *
   * @param samCommand The command to be added.
   * @since 0.3.0
   */
  final void addTargetSamCommand(Command samCommand) {
    targetSamCommands.add(samCommand);
  }

  /**
   * Gets the the list of added target SAM commands.
   *
   * @return A not null list of commands.
   * @since 0.3.0
   */
  List<Command> getTargetSamCommands() {
    return targetSamCommands;
  }

  /**
   * Executes all previously added commands for the target SAM. If a command needs to be finalized,
   * especially with the help of a control SAM, then it will be.
   *
   * @param closePhysicalChannel True if the physical channel must be closed after the operation.
   * @since 0.3.0
   */
  final void processTargetSamCommands(boolean closePhysicalChannel) {
    try {
      CommandExecutor.processCommands(targetSamCommands, targetSamReader, closePhysicalChannel);
    } catch (RuntimeException e) {
      resetState();
      throw e;
    } finally {
      cleanState();
    }
  }

  /**
   * Executes all previously added commands for the target SAM when they are already finalized (in
   * an asynchronous operation for example).
   *
   * @param closePhysicalChannel True if the physical channel must be closed after the operation.
   * @since 0.3.0
   */
  final void processTargetSamCommandsAlreadyFinalized(boolean closePhysicalChannel) {
    try {
      CommandExecutor.processCommandsAlreadyFinalized(
          targetSamCommands, targetSamReader, closePhysicalChannel);
    } catch (RuntimeException e) {
      resetState();
      throw e;
    } finally {
      cleanState();
    }
  }

  /**
   * Resets any variables in the class.
   *
   * @since 0.3.0
   */
  private void resetState() {}

  /**
   * Clears the list of target SAM commands.
   *
   * @since 0.3.0
   */
  private void cleanState() {
    targetSamCommands.clear();
  }

  /**
   * Executes all provided commands for the target SAM. If a command needs to be finalized,
   * especially with the help of a control SAM, then it will be.
   *
   * <p>The method leaves the physical channel open, allowing for subsequent commands to be executed
   * on the same reader.
   *
   * @param commands A not null list of {@link Command}.
   * @since 0.3.0
   */
  final void processTargetSamCommands(List<Command> commands) {
    CommandExecutor.processCommands(commands, targetSamReader, false);
  }
}
