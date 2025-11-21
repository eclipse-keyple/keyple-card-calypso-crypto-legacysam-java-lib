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
import org.eclipse.keypop.card.*;
import org.eclipse.keypop.reader.ChannelControl;

/**
 * Abstract class of all transaction manager adapters.
 *
 * @since 0.3.0
 */
abstract class CommonTransactionManagerAdapter {
  /* JSON field names */
  static final String SAM_COMMANDS_TYPES = "samCommandsTypes";
  static final String SAM_COMMANDS = "samCommands";

  private final ProxyReaderApi targetSamReader;
  private final LegacySamAdapter targetSam;
  private final ProxyReaderApi controlSamReader;
  private final LegacySamAdapter controlSam;
  private final List<Command> targetSamCommands = new ArrayList<>();

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
   * Gets the list of added target SAM commands.
   *
   * @return A not null list of commands.
   * @since 0.3.0
   */
  final List<Command> getTargetSamCommands() {
    return targetSamCommands;
  }

  /**
   * Executes all previously added commands for the target SAM. If a command needs to be finalized,
   * especially with the help of a control SAM, then it will be.
   *
   * @param channelControl The channel control.
   * @since 1.0.0
   */
  final void processTargetSamCommands(ChannelControl channelControl) {
    try {
      CommandExecutor.processCommands(targetSamCommands, targetSamReader, channelControl);
    } finally {
      targetSamCommands.clear();
    }
  }

  /**
   * Executes all previously added commands for the target SAM when they are already finalized (in
   * an asynchronous operation for example).
   *
   * @param channelControl The channel control.
   * @since 1.0.0
   */
  final void processTargetSamCommandsAlreadyFinalized(ChannelControl channelControl) {
    try {
      CommandExecutor.processCommandsAlreadyFinalized(
          targetSamCommands, targetSamReader, channelControl);
    } finally {
      targetSamCommands.clear();
    }
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
  final void processTargetSamCommands(List<? extends Command> commands) {
    CommandExecutor.processCommands(commands, targetSamReader, ChannelControl.KEEP_OPEN);
  }
}
