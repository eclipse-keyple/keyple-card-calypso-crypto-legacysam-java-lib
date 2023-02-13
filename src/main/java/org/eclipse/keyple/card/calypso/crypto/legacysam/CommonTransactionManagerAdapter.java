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
  static final String SAM_COMMANDS_TYPES = "samCommandsTypes";
  static final String SAM_COMMANDS = "samCommands";
  static final int[] counterToRecordLookup =
      new int[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2};
  private ProxyReaderApi targetSamReader;
  private LegacySamAdapter targetSam;
  private ProxyReaderApi controlSamReader;
  private LegacySamAdapter controlSam;
  private List<Command> targetSamCommands = new ArrayList<Command>();

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

  final ProxyReaderApi getTargetSamReader() {
    return targetSamReader;
  }

  final CommandContextDto getContext() {
    return new CommandContextDto(targetSam, controlSamReader, controlSam);
  }

  final void addTargetSamCommand(Command samCommand) {
    targetSamCommands.add(samCommand);
  }

  List<Command> getTargetSamCommands() {
    return targetSamCommands;
  }

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

  private void resetState() {}

  private void cleanState() {
    targetSamCommands.clear();
  }

  final void processTargetSamCommands(List<Command> commands) {
    CommandExecutor.processCommands(commands, targetSamReader, false);
  }

  final void finalizeTargetSamCommands(List<Command> commands) {
    CommandExecutor.processCommands(commands, targetSamReader, false);
  }
}
