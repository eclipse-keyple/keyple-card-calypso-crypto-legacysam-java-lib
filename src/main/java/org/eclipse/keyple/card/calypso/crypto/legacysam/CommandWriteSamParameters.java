/* **************************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://calypsonet.org/
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
import static org.eclipse.keyple.card.calypso.crypto.legacysam.DtoAdapters.CommandContextDto;

import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keypop.calypso.crypto.legacysam.SystemKeyType;
import org.eclipse.keypop.card.ApduResponseApi;

/**
 * Builds the Write Ceilings APDU command.
 *
 * @since 0.9.0
 */
final class CommandWriteSamParameters extends Command {
  private final transient TargetSamContextDto targetSamContext; // NOSONAR
  private final transient byte[] plainData = new byte[30]; // NOSONAR
  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<>(Command.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc", IllegalParameterException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Preconditions not satisfied:\n"
                + "- The SAM is locked.\n"
                + "- In P1, b7 is equal to 1.\n"
                + "- CipherEnableBit of PAR1 is 0.\n"
                + "- Dynamic mode and the outgoing challenge is unavailable.\n"
                + "- SystemLockEnableBit=1.\n"
                + "- Static mode and StaticCipherEnableBit=0",
            AccessForbiddenException.class));
    m.put(
        0x6900,
        new StatusProperties(
            "An event counter cannot be incremented", CounterOverflowException.class));
    m.put(0x6988, new StatusProperties("Incorrect signature", SecurityDataException.class));
    m.put(0x6A00, new StatusProperties("Incorrect P2", IllegalParameterException.class));
    m.put(
        0x6A80,
        new StatusProperties("Incorrect decrypted data", IncorrectInputDataException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found: deciphering key not found", DataAccessException.class));
    STATUS_TABLE = m;
  }

  /**
   * Instantiates a new CommandWriteCeilings for writing a single ceiling value.
   *
   * @param context The command context.
   * @param targetSamContext The target SAM context.
   * @param samParameters The SAM parameters to write.
   * @since 0.9.0
   */
  CommandWriteSamParameters(
      CommandContextDto context, TargetSamContextDto targetSamContext, byte[] samParameters) {

    super(CommandRef.WRITE_PARAMETERS, 0, context);

    this.targetSamContext = targetSamContext;

    // build the plain data block to be ciphered later
    plainData[0] = targetSamContext.getSystemKeyTypeToKvcMap().get(SystemKeyType.PERSONALIZATION);
    System.arraycopy(samParameters, 0, plainData, 1, samParameters.length);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  void finalizeRequest() {
    CommandContextDto controlSamContext =
        new CommandContextDto(getContext().getControlSam(), null, null);
    // add commands
    addControlSamCommand(
        new CommandSelectDiversifier(controlSamContext, targetSamContext.getSerialNumber()));
    byte[] challenge =
        targetSamContext.isDynamicMode()
            ? getContext().getTargetSam().popChallenge()
            : LegacySamUtil.computeStaticModeChallenge(
                targetSamContext, SystemKeyType.PERSONALIZATION);
    addControlSamCommand(new CommandGiveRandom(controlSamContext, challenge));
    CommandSamDataCipher commandSamDataCipher =
        new CommandSamDataCipher(
            controlSamContext, 0, CommandSamDataCipher.DataType.PARAMETERS_RECORD, plainData);
    addControlSamCommand(commandSamDataCipher);
    processControlSamCommand();
    final byte cla = getContext().getTargetSam().getClassByte();
    final byte inst = CommandRef.WRITE_PARAMETERS.getInstructionByte();
    final byte p1 = targetSamContext.isDynamicMode() ? (byte) 0x00 : (byte) 0x08;
    final byte p2 = (byte) 0xA0;
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, inst, p1, p2, commandSamDataCipher.getCipheredData(), null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  boolean isControlSamRequiredToFinalizeRequest() {
    return true;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  void parseResponse(ApduResponseApi apduResponse) throws CommandException {
    setResponseAndCheckStatus(apduResponse);
  }
}
