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

import static org.eclipse.keyple.card.calypso.crypto.legacysam.DtoAdapters.ApduRequestAdapter;
import static org.eclipse.keyple.card.calypso.crypto.legacysam.DtoAdapters.CommandContextDto;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keypop.calypso.crypto.legacysam.GetDataTag;
import org.eclipse.keypop.card.ApduResponseApi;

/**
 * Builds the Get Challenge APDU command.
 *
 * @since 0.6.0
 */
final class CommandGetData extends Command {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<>(Command.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Le", IllegalParameterException.class));
    m.put(
        0x6A88,
        new StatusProperties("Data referenced by P1-P2 not available", DataAccessException.class));
    STATUS_TABLE = m;
  }

  private final LegacySamConstants.TagInfo tagInfo;

  /**
   * Instantiates a new CmdSamGetChallenge.
   *
   * @param context The command context.
   * @param tag The tag to retrieve the data for.
   * @since 0.6.0
   */
  CommandGetData(CommandContextDto context, GetDataTag tag) {
    super(CommandRef.GET_DATA, getExpectedTotalLength(tag), context);

    this.tagInfo = LegacySamConstants.TagInfo.valueOf(tag.name());

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                context.getTargetSam().getClassByte(),
                getCommandRef().getInstructionByte(),
                tagInfo.getMsb(),
                tagInfo.getLsb(),
                null,
                (byte) Math.min(tagInfo.getLength(), 255))));
  }

  private static int getExpectedTotalLength(GetDataTag tag) {
    return LegacySamConstants.TagInfo.valueOf(tag.name()).getTotalLength();
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.6.0
   */
  @Override
  void finalizeRequest() {
    /* nothing to do */
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.6.0
   */
  @Override
  boolean isControlSamRequiredToFinalizeRequest() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.6.0
   */
  @Override
  void parseResponse(ApduResponseApi apduResponse) throws CommandException {
    setResponseAndCheckStatus(apduResponse);
    byte[] dataOut = apduResponse.getDataOut();
    // check BER-TLV header
    byte[] header = tagInfo.getHeader();
    for (int i = 0; i < header.length; i++) {
      if (dataOut[i] != header[i]) {
        throw new DataAccessException("Inconsistent BER-TLV tag");
      }
    }
    getContext()
        .getTargetSam()
        .setCaCertificate(Arrays.copyOfRange(dataOut, header.length, dataOut.length));
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.6.0
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }
}
