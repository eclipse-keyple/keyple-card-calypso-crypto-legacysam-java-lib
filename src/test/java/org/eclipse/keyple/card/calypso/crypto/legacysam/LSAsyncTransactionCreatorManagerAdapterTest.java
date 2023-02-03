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

import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.keyple.card.calypso.crypto.legacysam.DtoAdapters.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import org.calypsonet.terminal.calypso.crypto.legacysam.sam.LegacySam;
import org.calypsonet.terminal.calypso.crypto.legacysam.transaction.LSAsyncTransactionCreatorManager;
import org.calypsonet.terminal.calypso.crypto.legacysam.transaction.LSSecuritySetting;
import org.calypsonet.terminal.card.*;
import org.calypsonet.terminal.card.spi.ApduRequestSpi;
import org.calypsonet.terminal.card.spi.CardRequestSpi;
import org.calypsonet.terminal.reader.CardReader;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keyple.core.util.json.JsonUtil;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatcher;

public class LSAsyncTransactionCreatorManagerAdapterTest {

  private static final String SAM_SERIAL_NUMBER = "11223344";
  private static final String R_9000 = "9000";
  private static final String R_INCORRECT_SIGNATURE = "6988";
  private static final String SAM_C1_POWER_ON_DATA =
      "3B3F9600805A4880C1205017" + SAM_SERIAL_NUMBER + "82" + R_9000;
  private static final String C_SELECT_DIVERSIFIER = "8014000004" + SAM_SERIAL_NUMBER;
  private static final String C_GIVE_RANDOM_COUNTER_RELOADING = "8086000008000000000000017B";
  private static final String C_SAM_DATA_CIPHER_CEILING_0 =
      "801600B81D0000006400000000000000000000000000000000000000000000000000";
  private static final String SAM_DATA_CIPHER_CEILING_0 =
      "040990EDF6C0D2F9FEF25629BEB6439B762DDCD97A90AAAD6CAACCFDD75C6209AC7ABCBF6560A7D2ACC1594441B1E32A";
  private static final String R_SAM_DATA_CIPHER_CEILING_0 = SAM_DATA_CIPHER_CEILING_0 + R_9000;

  private static final String TARGET_SAM_CONTEXT =
      "{\"serialNumber\":\"11223344\","
          + "\"systemKeyTypeToCounterNumberMap\":"
          + "{"
          + "\"PERSONALIZATION\":\"01\","
          + "\"KEY_MANAGEMENT\":\"02\","
          + "\"RELOADING\":\"03\""
          + "},"
          + "\"counterNumberToCounterValueMap\":"
          + "{"
          + "\"01\":\"0179\","
          + "\"02\":\"017A\","
          + "\"03\":\"017B\""
          + "}"
          + "}";
  private LSAsyncTransactionCreatorManager samTransactionManager;
  private ReaderMock samReader;
  private LegacySam controlSam;

  interface ReaderMock extends CardReader, ProxyReaderApi {}

  @Before
  public void setUp() {

    samReader = mock(LSAsyncTransactionCreatorManagerAdapterTest.ReaderMock.class);

    CardSelectionResponseApi samCardSelectionResponse = mock(CardSelectionResponseApi.class);
    when(samCardSelectionResponse.getPowerOnData()).thenReturn(SAM_C1_POWER_ON_DATA);
    controlSam = new LegacySamAdapter(samCardSelectionResponse);

    LSFreeTransactionManagerAdapterTest.ReaderMock controlSamReader =
        mock(LSFreeTransactionManagerAdapterTest.ReaderMock.class);

    when(samCardSelectionResponse.getPowerOnData()).thenReturn(SAM_C1_POWER_ON_DATA);
    LegacySam controlSam = new LegacySamAdapter(samCardSelectionResponse);

    LSSecuritySetting securitySetting =
        new LSSecuritySettingAdapter().setControlSamResource(samReader, controlSam);

    samTransactionManager =
        LegacySamCardExtensionService.getInstance()
            .getTransactionManagerFactory()
            .createAsyncTransactionCreatorManager(TARGET_SAM_CONTEXT, securitySetting);
  }

  private CardRequestSpi createCardRequest(String... apduCommands) {
    List<ApduRequestSpi> apduRequests = new ArrayList<ApduRequestSpi>();
    for (String apduCommand : apduCommands) {
      apduRequests.add(new ApduRequestAdapter(HexUtil.toByteArray(apduCommand)));
    }
    return new CardRequestAdapter(apduRequests, false);
  }

  private CardResponseApi createCardResponse(String... apduCommandResponses) {
    List<ApduResponseApi> apduResponses = new ArrayList<ApduResponseApi>();
    for (String apduResponse : apduCommandResponses) {
      apduResponses.add(new TestDtoAdapters.ApduResponseAdapter(HexUtil.toByteArray(apduResponse)));
    }
    return new TestDtoAdapters.CardResponseAdapter(apduResponses, true);
  }

  private static class CardRequestMatcher implements ArgumentMatcher<CardRequestSpi> {
    List<ApduRequestSpi> leftApduRequests;

    CardRequestMatcher(CardRequestSpi cardRequest) {
      leftApduRequests = cardRequest.getApduRequests();
    }

    @Override
    public boolean matches(CardRequestSpi right) {
      if (right == null) {
        return false;
      }
      List<ApduRequestSpi> rightApduRequests = right.getApduRequests();
      if (leftApduRequests.size() != rightApduRequests.size()) {
        return false;
      }
      Iterator<ApduRequestSpi> itLeft = leftApduRequests.iterator();
      Iterator<ApduRequestSpi> itRight = rightApduRequests.iterator();
      while (itLeft.hasNext() && itRight.hasNext()) {
        byte[] leftApdu = itLeft.next().getApdu();
        byte[] rightApdu = itRight.next().getApdu();
        if (!Arrays.equals(leftApdu, rightApdu)) {
          return false;
        }
      }
      return true;
    }
  }

  @Test
  public void exportCommands_shouldProduceJsonCommandList() throws Exception {
    CardRequestSpi cardRequestCipherData =
        createCardRequest(
            C_SELECT_DIVERSIFIER, C_GIVE_RANDOM_COUNTER_RELOADING, C_SAM_DATA_CIPHER_CEILING_0);
    CardResponseApi cardResponseKeyParam =
        createCardResponse(R_9000, R_9000, R_SAM_DATA_CIPHER_CEILING_0);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequestCipherData)), any(ChannelControl.class)))
        .thenReturn(cardResponseKeyParam);

    samTransactionManager.prepareWriteEventCeiling(0, 100);
    String commands = samTransactionManager.exportCommands();
    SamCommandsDto expectedSamCommandsDto = new SamCommandsDto();
    expectedSamCommandsDto.add(
        new ApduRequestAdapter(
            ApduUtil.build(
                (byte) 0x80,
                (byte) 0xD8,
                (byte) 0x00,
                (byte) 0xB8,
                HexUtil.toByteArray(SAM_DATA_CIPHER_CEILING_0),
                null)));
    String expectedSamCommands = JsonUtil.toJson(expectedSamCommandsDto);
    assertThat(commands).isEqualTo(expectedSamCommands);
  }
}
