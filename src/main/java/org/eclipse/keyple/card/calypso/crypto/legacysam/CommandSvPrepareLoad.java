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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keypop.calypso.crypto.symmetric.SvCommandSecurityDataApi;
import org.eclipse.keypop.card.ApduResponseApi;

/**
 * Builds the SV Prepare Load APDU command.
 *
 * @since 2.0.1
 */
final class CommandSvPrepareLoad extends Command {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<>(Command.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc", IllegalParameterException.class));
    m.put(
        0x6985,
        new StatusProperties("Preconditions not satisfied", AccessForbiddenException.class));
    m.put(0x6A00, new StatusProperties("Incorrect P1 or P2", IllegalParameterException.class));
    m.put(
        0x6A80, new StatusProperties("Incorrect incoming data", IncorrectInputDataException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found: ciphering key not found", DataAccessException.class));
    STATUS_TABLE = m;
  }

  private final SvCommandSecurityDataApi data;

  /**
   * Instantiates a new CommandSvPrepareLoad to prepare a load transaction.
   *
   * <p>Build the SvPrepareLoad APDU from the SvGet command and response, the SvReload partial
   * command
   *
   * @param context The command context.
   * @param data The SV input/output command data.
   * @since 2.0.1
   */
  CommandSvPrepareLoad(DtoAdapters.CommandContextDto context, SvCommandSecurityDataApi data) {

    super(CommandRef.SV_PREPARE_LOAD, 0, context);

    this.data = data;

    byte cla = context.getTargetSam().getClassByte();
    byte p1 = (byte) 0x01;
    byte p2 = (byte) 0xFF;
    byte[] dataIn =
        new byte[19 + data.getSvGetResponse().length]; // header(4) + SvReload data (15) = 19 bytes

    System.arraycopy(data.getSvGetRequest(), 0, dataIn, 0, 4);
    System.arraycopy(data.getSvGetResponse(), 0, dataIn, 4, data.getSvGetResponse().length);
    System.arraycopy(
        data.getSvCommandPartialRequest(),
        0,
        dataIn,
        4 + data.getSvGetResponse().length,
        data.getSvCommandPartialRequest().length);

    setApduRequest(
        new DtoAdapters.ApduRequestAdapter(
            ApduUtil.build(cla, getCommandRef().getInstructionByte(), p1, p2, dataIn, null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.4.0
   */
  @Override
  void finalizeRequest() {
    /* nothing to do */
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.4.0
   */
  @Override
  boolean isControlSamRequiredToFinalizeRequest() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.4.0
   */
  @Override
  void parseResponse(ApduResponseApi apduResponse) throws CommandException {
    setResponseAndCheckStatus(apduResponse);
    byte[] dataOut = apduResponse.getDataOut();
    data.setSerialNumber(getContext().getTargetSam().getSerialNumber())
        .setTerminalChallenge(Arrays.copyOfRange(dataOut, 0, 3))
        .setTransactionNumber(Arrays.copyOfRange(dataOut, 3, 6))
        .setTerminalSvMac(Arrays.copyOfRange(dataOut, 6, dataOut.length));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.1
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }
}
