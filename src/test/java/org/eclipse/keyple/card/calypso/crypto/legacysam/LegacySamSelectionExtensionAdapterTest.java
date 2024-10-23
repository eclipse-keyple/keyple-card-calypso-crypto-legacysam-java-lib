/* **************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/
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
import static org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySam.*;
import static org.mockito.Mockito.*;

import java.util.*;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.crypto.legacysam.SystemKeyType;
import org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySam;
import org.eclipse.keypop.calypso.crypto.legacysam.spi.LegacySamDynamicUnlockDataProviderSpi;
import org.eclipse.keypop.calypso.crypto.legacysam.spi.LegacySamStaticUnlockDataProviderSpi;
import org.eclipse.keypop.card.*;
import org.eclipse.keypop.card.spi.ApduRequestSpi;
import org.eclipse.keypop.card.spi.CardRequestSpi;
import org.eclipse.keypop.reader.CardReader;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.InOrder;

public final class LegacySamSelectionExtensionAdapterTest {

  private static final String SW_9000 = "9000";
  private static final String SAM_SERIAL_NUMBER = "11223344";
  private static final String SAM_ATR =
      "3B3F9600805AAABBC1DDEEFF" + SAM_SERIAL_NUMBER + "82" + SW_9000;
  private static final String UNLOCK_DATA_STATIC = "00112233445566778899AABBCCDDEEFF";
  private static final String UNLOCK_DATA_DYNAMIC = "0011223344556677";
  private static final String CMD_UNLOCK_STATIC = "8020000010" + UNLOCK_DATA_STATIC;
  private static final String CMD_UNLOCK_DYNAMIC = "8020000008" + UNLOCK_DATA_DYNAMIC;
  private static final String SAM_CHALLENGE = "1122334455667788";
  private static final String CMD_GET_CHALLENGE = "8084000008";
  private static final String RESP_GET_CHALLENGE = SAM_CHALLENGE + SW_9000;
  private static final String CMD_READ_SYSTEM_KEY_PARAMETERS = "80BC00C1020000";
  private static final String RESP_READ_SYSTEM_KEY_PARAMETERS_DATA_OUT =
      "1122334455667788" + "112233445566778899AABBCCDD" + "112233445566778899AABB";
  private static final String RESP_READ_SYSTEM_KEY_PARAMETERS =
      RESP_READ_SYSTEM_KEY_PARAMETERS_DATA_OUT + SW_9000;
  private LegacySamSelectionExtensionAdapter samSelectionExtension;
  private LegacySamStaticUnlockDataProviderSpi staticUnlockDataProvider;
  private LegacySamDynamicUnlockDataProviderSpi dynamicUnlockDataProvider;
  private SamReader samReader;

  private interface SamReader extends CardReader, ProxyReaderApi {}

  private static CardRequestSpi createCardRequest(String... apduCommands) {
    List<ApduRequestSpi> apduRequests = new ArrayList<ApduRequestSpi>();
    for (String apduCommand : apduCommands) {
      apduRequests.add(new DtoAdapters.ApduRequestAdapter(HexUtil.toByteArray(apduCommand)));
    }
    return new DtoAdapters.CardRequestAdapter(apduRequests, false);
  }

  private static CardResponseApi createCardResponse(String... apduCommandResponses) {
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
    public final boolean matches(CardRequestSpi argument) {
      if (argument == null) {
        return false;
      }
      List<ApduRequestSpi> rightApduRequests = argument.getApduRequests();
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

  @Before
  public void setUp() {
    samSelectionExtension =
        (LegacySamSelectionExtensionAdapter)
            LegacySamExtensionService.getInstance()
                .getLegacySamApiFactory()
                .createLegacySamSelectionExtension();
    staticUnlockDataProvider = mock(LegacySamStaticUnlockDataProviderSpi.class);
    dynamicUnlockDataProvider = mock(LegacySamDynamicUnlockDataProviderSpi.class);
    samReader = mock(SamReader.class);
  }

  @Test(expected = IllegalArgumentException.class)
  public void setUnlockData_whenUnlockDataIsNull_shouldThrowIAE() {
    samSelectionExtension.setUnlockData(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void setUnlockData_whenUnlockDataHasABadLength_shouldThrowIAE() {
    samSelectionExtension.setUnlockData("00112233445566778899AABBCCDDEE");
  }

  @Test(expected = IllegalArgumentException.class)
  public void setUnlockData_whenUnlockDataIsInvalid_shouldThrowIAE() {
    samSelectionExtension.setUnlockData("00112233445566778899AABBCCDDEEGG");
  }

  @Test(expected = IllegalStateException.class)
  public void setUnlockData_whenUnlockModeIsAlreadySet_shouldThrowISE_1() {
    samSelectionExtension.setStaticUnlockDataProvider(staticUnlockDataProvider);
    samSelectionExtension.setUnlockData(UNLOCK_DATA_STATIC);
  }

  @Test(expected = IllegalStateException.class)
  public void setUnlockData_whenUnlockModeIsAlreadySet_shouldThrowISE_2() {
    samSelectionExtension.setStaticUnlockDataProvider(staticUnlockDataProvider, samReader);
    samSelectionExtension.setUnlockData(UNLOCK_DATA_STATIC);
  }

  @Test(expected = IllegalStateException.class)
  public void setUnlockData_whenUnlockModeIsAlreadySet_shouldThrowISE_3() {
    samSelectionExtension.setDynamicUnlockDataProvider(dynamicUnlockDataProvider);
    samSelectionExtension.setUnlockData(UNLOCK_DATA_STATIC);
  }

  @Test(expected = IllegalStateException.class)
  public void setUnlockData_whenUnlockModeIsAlreadySet_shouldThrowISE_4() {
    samSelectionExtension.setDynamicUnlockDataProvider(dynamicUnlockDataProvider, samReader);
    samSelectionExtension.setUnlockData(UNLOCK_DATA_STATIC);
  }

  @Test(expected = IllegalArgumentException.class)
  public void setStaticUnlockDataProvider_1param_whenProviderIsNull_shouldThrowIAE() {
    samSelectionExtension.setStaticUnlockDataProvider(null);
  }

  @Test(expected = IllegalStateException.class)
  public void setStaticUnlockDataProvider_1param_whenUnlockModeIsAlreadySet_shouldThrowISE_1() {
    samSelectionExtension.setUnlockData(UNLOCK_DATA_STATIC);
    samSelectionExtension.setStaticUnlockDataProvider(staticUnlockDataProvider);
  }

  @Test(expected = IllegalStateException.class)
  public void setStaticUnlockDataProvider_1param_whenUnlockModeIsAlreadySet_shouldThrowISE_2() {
    samSelectionExtension.setStaticUnlockDataProvider(staticUnlockDataProvider, samReader);
    samSelectionExtension.setStaticUnlockDataProvider(staticUnlockDataProvider);
  }

  @Test(expected = IllegalStateException.class)
  public void setStaticUnlockDataProvider_1param_whenUnlockModeIsAlreadySet_shouldThrowISE_3() {
    samSelectionExtension.setDynamicUnlockDataProvider(dynamicUnlockDataProvider);
    samSelectionExtension.setStaticUnlockDataProvider(staticUnlockDataProvider);
  }

  @Test(expected = IllegalStateException.class)
  public void setStaticUnlockDataProvider_1param_whenUnlockModeIsAlreadySet_shouldThrowISE_4() {
    samSelectionExtension.setDynamicUnlockDataProvider(dynamicUnlockDataProvider, samReader);
    samSelectionExtension.setStaticUnlockDataProvider(staticUnlockDataProvider);
  }

  @Test(expected = IllegalArgumentException.class)
  public void setStaticUnlockDataProvider_2params_whenProviderIsNull_shouldThrowIAE() {
    samSelectionExtension.setStaticUnlockDataProvider(null, samReader);
  }

  @Test(expected = IllegalArgumentException.class)
  public void setStaticUnlockDataProvider_2params_whenSamReaderIsNull_shouldThrowIAE() {
    samSelectionExtension.setStaticUnlockDataProvider(staticUnlockDataProvider, null);
  }

  @Test(expected = IllegalStateException.class)
  public void setStaticUnlockDataProvider_2params_whenUnlockModeIsAlreadySet_shouldThrowISE_1() {
    samSelectionExtension.setUnlockData(UNLOCK_DATA_STATIC);
    samSelectionExtension.setStaticUnlockDataProvider(staticUnlockDataProvider, samReader);
  }

  @Test(expected = IllegalStateException.class)
  public void setStaticUnlockDataProvider_2params_whenUnlockModeIsAlreadySet_shouldThrowISE_2() {
    samSelectionExtension.setStaticUnlockDataProvider(staticUnlockDataProvider);
    samSelectionExtension.setStaticUnlockDataProvider(staticUnlockDataProvider, samReader);
  }

  @Test(expected = IllegalStateException.class)
  public void setStaticUnlockDataProvider_2params_whenUnlockModeIsAlreadySet_shouldThrowISE_3() {
    samSelectionExtension.setDynamicUnlockDataProvider(dynamicUnlockDataProvider);
    samSelectionExtension.setStaticUnlockDataProvider(staticUnlockDataProvider, samReader);
  }

  @Test(expected = IllegalStateException.class)
  public void setStaticUnlockDataProvider_2params_whenUnlockModeIsAlreadySet_shouldThrowISE_4() {
    samSelectionExtension.setDynamicUnlockDataProvider(dynamicUnlockDataProvider, samReader);
    samSelectionExtension.setStaticUnlockDataProvider(staticUnlockDataProvider, samReader);
  }

  @Test(expected = IllegalArgumentException.class)
  public void setDynamicUnlockDataProvider_1param_whenProviderIsNull_shouldThrowIAE() {
    samSelectionExtension.setDynamicUnlockDataProvider(null);
  }

  @Test(expected = IllegalStateException.class)
  public void setDynamicUnlockDataProvider_1param_whenUnlockModeIsAlreadySet_shouldThrowISE_1() {
    samSelectionExtension.setUnlockData(UNLOCK_DATA_STATIC);
    samSelectionExtension.setDynamicUnlockDataProvider(dynamicUnlockDataProvider);
  }

  @Test(expected = IllegalStateException.class)
  public void setDynamicUnlockDataProvider_1param_whenUnlockModeIsAlreadySet_shouldThrowISE_2() {
    samSelectionExtension.setStaticUnlockDataProvider(staticUnlockDataProvider);
    samSelectionExtension.setDynamicUnlockDataProvider(dynamicUnlockDataProvider);
  }

  @Test(expected = IllegalStateException.class)
  public void setDynamicUnlockDataProvider_1param_whenUnlockModeIsAlreadySet_shouldThrowISE_3() {
    samSelectionExtension.setStaticUnlockDataProvider(staticUnlockDataProvider, samReader);
    samSelectionExtension.setDynamicUnlockDataProvider(dynamicUnlockDataProvider);
  }

  @Test(expected = IllegalStateException.class)
  public void setDynamicUnlockDataProvider_1param_whenUnlockModeIsAlreadySet_shouldThrowISE_4() {
    samSelectionExtension.setDynamicUnlockDataProvider(dynamicUnlockDataProvider, samReader);
    samSelectionExtension.setDynamicUnlockDataProvider(dynamicUnlockDataProvider);
  }

  @Test(expected = IllegalArgumentException.class)
  public void setDynamicUnlockDataProvider_2params_whenProviderIsNull_shouldThrowIAE() {
    samSelectionExtension.setDynamicUnlockDataProvider(null, samReader);
  }

  @Test(expected = IllegalArgumentException.class)
  public void setDynamicUnlockDataProvider_2params_whenSamReaderIsNull_shouldThrowIAE() {
    samSelectionExtension.setDynamicUnlockDataProvider(dynamicUnlockDataProvider, null);
  }

  @Test(expected = IllegalStateException.class)
  public void setDynamicUnlockDataProvider_2params_whenUnlockModeIsAlreadySet_shouldThrowISE_1() {
    samSelectionExtension.setUnlockData(UNLOCK_DATA_STATIC);
    samSelectionExtension.setDynamicUnlockDataProvider(dynamicUnlockDataProvider, samReader);
  }

  @Test(expected = IllegalStateException.class)
  public void setDynamicUnlockDataProvider_2params_whenUnlockModeIsAlreadySet_shouldThrowISE_2() {
    samSelectionExtension.setStaticUnlockDataProvider(staticUnlockDataProvider);
    samSelectionExtension.setDynamicUnlockDataProvider(dynamicUnlockDataProvider, samReader);
  }

  @Test(expected = IllegalStateException.class)
  public void setDynamicUnlockDataProvider_2params_whenUnlockModeIsAlreadySet_shouldThrowISE_3() {
    samSelectionExtension.setStaticUnlockDataProvider(staticUnlockDataProvider, samReader);
    samSelectionExtension.setDynamicUnlockDataProvider(dynamicUnlockDataProvider, samReader);
  }

  @Test(expected = IllegalStateException.class)
  public void setDynamicUnlockDataProvider_2params_whenUnlockModeIsAlreadySet_shouldThrowISE_4() {
    samSelectionExtension.setDynamicUnlockDataProvider(dynamicUnlockDataProvider);
    samSelectionExtension.setDynamicUnlockDataProvider(dynamicUnlockDataProvider, samReader);
  }

  @Test
  public void getCardSelectionRequest_whenUnlockIsNotSet_shouldReturnAllPreparedApdus() {
    samSelectionExtension.prepareReadSystemKeyParameters(SystemKeyType.PERSONALIZATION);
    List<ApduRequestSpi> apduRequests =
        samSelectionExtension.getCardSelectionRequest().getCardRequest().getApduRequests();
    assertThat(apduRequests).hasSize(1);
    assertThat(apduRequests.get(0).getApdu())
        .isEqualTo(HexUtil.toByteArray(CMD_READ_SYSTEM_KEY_PARAMETERS));
  }

  @Test
  public void
      getCardSelectionRequest_whenUnlockPlainModeIsSet_shouldReturnAllPreparedApdusWithUnlockCommandAtFirstIndex() {
    samSelectionExtension.prepareReadSystemKeyParameters(SystemKeyType.PERSONALIZATION);
    samSelectionExtension.setUnlockData(UNLOCK_DATA_STATIC);
    List<ApduRequestSpi> apduRequests =
        samSelectionExtension.getCardSelectionRequest().getCardRequest().getApduRequests();
    assertThat(apduRequests).hasSize(2);
    assertThat(apduRequests.get(0).getApdu()).isEqualTo(HexUtil.toByteArray(CMD_UNLOCK_STATIC));
    assertThat(apduRequests.get(1).getApdu())
        .isEqualTo(HexUtil.toByteArray(CMD_READ_SYSTEM_KEY_PARAMETERS));
  }

  @Test
  public void getCardSelectionRequest_whenUnlockStaticModeIsSet_shouldReturnEmptyList_1() {
    samSelectionExtension.prepareReadSystemKeyParameters(SystemKeyType.PERSONALIZATION);
    samSelectionExtension.setStaticUnlockDataProvider(staticUnlockDataProvider);
    assertThat(samSelectionExtension.getCardSelectionRequest().getCardRequest()).isNull();
  }

  @Test
  public void getCardSelectionRequest_whenUnlockStaticModeIsSet_shouldReturnEmptyList_2() {
    samSelectionExtension.prepareReadSystemKeyParameters(SystemKeyType.PERSONALIZATION);
    samSelectionExtension.setStaticUnlockDataProvider(staticUnlockDataProvider, samReader);
    assertThat(samSelectionExtension.getCardSelectionRequest().getCardRequest()).isNull();
  }

  @Test
  public void
      getCardSelectionRequest_whenUnlockDynamicModeIsSet_shouldReturnAListWithOnlyGetChallengeCommand_1() {
    samSelectionExtension.prepareReadSystemKeyParameters(SystemKeyType.PERSONALIZATION);
    samSelectionExtension.setDynamicUnlockDataProvider(dynamicUnlockDataProvider);
    List<ApduRequestSpi> apduRequests =
        samSelectionExtension.getCardSelectionRequest().getCardRequest().getApduRequests();
    assertThat(apduRequests).hasSize(1);
    assertThat(apduRequests.get(0).getApdu()).isEqualTo(HexUtil.toByteArray(CMD_GET_CHALLENGE));
  }

  @Test
  public void
      getCardSelectionRequest_whenUnlockDynamicModeIsSet_shouldReturnAListWithOnlyGetChallengeCommand_2() {
    samSelectionExtension.prepareReadSystemKeyParameters(SystemKeyType.PERSONALIZATION);
    samSelectionExtension.setDynamicUnlockDataProvider(dynamicUnlockDataProvider, samReader);
    List<ApduRequestSpi> apduRequests =
        samSelectionExtension.getCardSelectionRequest().getCardRequest().getApduRequests();
    assertThat(apduRequests).hasSize(1);
    assertThat(apduRequests.get(0).getApdu()).isEqualTo(HexUtil.toByteArray(CMD_GET_CHALLENGE));
  }

  @Test(expected = ParseException.class)
  public void parse_whenCommandsResponsesMismatch_shouldThrowIDE() throws Exception {
    CardSelectionResponseApi cardSelectionResponseApi = mock(CardSelectionResponseApi.class);
    when(cardSelectionResponseApi.getPowerOnData()).thenReturn(SAM_ATR);
    samSelectionExtension.setUnlockData(UNLOCK_DATA_STATIC);
    samSelectionExtension.getCardSelectionRequest();
    samSelectionExtension.parse(cardSelectionResponseApi);
  }

  @Test(expected = ParseException.class)
  public void parse_whenUnlockFailed_shouldThrowParseException() throws Exception {
    CardSelectionResponseApi cardSelectionResponseApi = mock(CardSelectionResponseApi.class);
    CardResponseApi cardResponseApi = mock(CardResponseApi.class);
    ApduResponseApi apduResponseApi = mock(ApduResponseApi.class);
    List<ApduResponseApi> apduResponseApis = Collections.singletonList(apduResponseApi);
    when(cardSelectionResponseApi.getPowerOnData()).thenReturn(SAM_ATR);
    ApduResponseApi unlockApduResponse = mock(ApduResponseApi.class);
    when(unlockApduResponse.getApdu()).thenReturn(HexUtil.toByteArray("6988"));
    when(unlockApduResponse.getStatusWord()).thenReturn(0x6988);
    when(cardSelectionResponseApi.getSelectApplicationResponse()).thenReturn(unlockApduResponse);
    when(cardSelectionResponseApi.getCardResponse()).thenReturn(cardResponseApi);
    when(cardResponseApi.getApduResponses()).thenReturn(apduResponseApis);
    samSelectionExtension.setUnlockData(UNLOCK_DATA_STATIC);
    samSelectionExtension.getCardSelectionRequest();
    samSelectionExtension.parse(cardSelectionResponseApi);
  }

  @Test
  public void parse_whenUnlockSucceed_shouldReturnLegacySam() throws Exception {
    CardSelectionResponseApi cardSelectionResponseApi = mock(CardSelectionResponseApi.class);
    CardResponseApi cardResponseApi = mock(CardResponseApi.class);
    when(cardSelectionResponseApi.getPowerOnData()).thenReturn(SAM_ATR);
    ApduResponseApi unlockApduResponse = mock(ApduResponseApi.class);
    List<ApduResponseApi> apduResponseApis = Collections.singletonList(unlockApduResponse);
    when(unlockApduResponse.getApdu()).thenReturn(HexUtil.toByteArray(SW_9000));
    when(unlockApduResponse.getStatusWord()).thenReturn(0x9000);
    when(cardSelectionResponseApi.getSelectApplicationResponse()).thenReturn(unlockApduResponse);
    when(cardSelectionResponseApi.getCardResponse()).thenReturn(cardResponseApi);
    when(cardResponseApi.getApduResponses()).thenReturn(apduResponseApis);
    samSelectionExtension.setUnlockData(UNLOCK_DATA_STATIC);
    samSelectionExtension.getCardSelectionRequest();
    LegacySam LegacySam = (LegacySam) samSelectionExtension.parse(cardSelectionResponseApi);
    assertThat(LegacySam).isNotNull();
    assertThat(LegacySam.getProductType()).isEqualTo(ProductType.SAM_C1);
    assertThat(LegacySam.getSerialNumber()).isEqualTo(HexUtil.toByteArray("11223344"));
    assertThat(LegacySam.getPlatform()).isEqualTo((byte) 0xAA);
    assertThat(LegacySam.getApplicationType()).isEqualTo((byte) 0xBB);
    assertThat(LegacySam.getApplicationSubType()).isEqualTo((byte) 0xC1);
    assertThat(LegacySam.getSoftwareIssuer()).isEqualTo((byte) 0xDD);
    assertThat(LegacySam.getSoftwareVersion()).isEqualTo((byte) 0xEE);
    assertThat(LegacySam.getSoftwareRevision()).isEqualTo((byte) 0xFF);
  }

  @Test(expected = ParseException.class)
  public void parse_whenUnlockStaticModeIsSetAndSamReaderIsNotSetLately_shouldThrowPE()
      throws Exception {
    CardSelectionResponseApi cardSelectionResponseApi = mock(CardSelectionResponseApi.class);
    when(cardSelectionResponseApi.getPowerOnData()).thenReturn(SAM_ATR);

    samSelectionExtension.prepareReadSystemKeyParameters(SystemKeyType.PERSONALIZATION);
    samSelectionExtension.setStaticUnlockDataProvider(staticUnlockDataProvider);
    samSelectionExtension.getCardSelectionRequest();
    samSelectionExtension.parse(cardSelectionResponseApi);
  }

  @Test
  public void
      parse_whenUnlockStaticModeIsSetAndSamReaderIsSet_shouldCallProviderAndTransmitAllCommands()
          throws Exception {

    // first selection response
    CardSelectionResponseApi cardSelectionResponseApi = mock(CardSelectionResponseApi.class);
    when(cardSelectionResponseApi.getPowerOnData()).thenReturn(SAM_ATR);
    when(cardSelectionResponseApi.getCardResponse()).thenReturn(null);

    // 2nd request/response
    CardRequestSpi cardRequest =
        createCardRequest(CMD_UNLOCK_STATIC, CMD_READ_SYSTEM_KEY_PARAMETERS);
    CardResponseApi cardResponse = createCardResponse(SW_9000, RESP_READ_SYSTEM_KEY_PARAMETERS);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    when(staticUnlockDataProvider.getUnlockData(HexUtil.toByteArray(SAM_SERIAL_NUMBER)))
        .thenReturn(HexUtil.toByteArray(UNLOCK_DATA_STATIC));

    samSelectionExtension.prepareReadSystemKeyParameters(SystemKeyType.PERSONALIZATION);
    samSelectionExtension.setStaticUnlockDataProvider(staticUnlockDataProvider, samReader);
    samSelectionExtension.getCardSelectionRequest();
    samSelectionExtension.parse(cardSelectionResponseApi);

    InOrder inOrder = inOrder(staticUnlockDataProvider, samReader);
    inOrder.verify(staticUnlockDataProvider).getUnlockData(HexUtil.toByteArray(SAM_SERIAL_NUMBER));
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(staticUnlockDataProvider, samReader);
  }

  @Test(expected = ParseException.class)
  public void parse_whenUnlockDynamicModeIsSetAndSamReaderIsNotSetLately_shouldThrowPE()
      throws Exception {
    CardSelectionResponseApi cardSelectionResponseApi = mock(CardSelectionResponseApi.class);
    when(cardSelectionResponseApi.getPowerOnData()).thenReturn(SAM_ATR);

    samSelectionExtension.prepareReadSystemKeyParameters(SystemKeyType.PERSONALIZATION);
    samSelectionExtension.setDynamicUnlockDataProvider(dynamicUnlockDataProvider);
    samSelectionExtension.getCardSelectionRequest();
    samSelectionExtension.parse(cardSelectionResponseApi);
  }

  @Test
  public void
      parse_whenUnlockDynamicModeIsSetAndSamReaderIsSet_shouldCallProviderAndTransmitAllCommands()
          throws Exception {

    // first selection response
    CardSelectionResponseApi cardSelectionResponseApi = mock(CardSelectionResponseApi.class);
    when(cardSelectionResponseApi.getPowerOnData()).thenReturn(SAM_ATR);
    when(cardSelectionResponseApi.getCardResponse())
        .thenReturn(createCardResponse(RESP_GET_CHALLENGE));

    // 2nd request/response
    CardRequestSpi cardRequest =
        createCardRequest(CMD_UNLOCK_DYNAMIC, CMD_READ_SYSTEM_KEY_PARAMETERS);
    CardResponseApi cardResponse = createCardResponse(SW_9000, RESP_READ_SYSTEM_KEY_PARAMETERS);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    when(dynamicUnlockDataProvider.getUnlockData(
            HexUtil.toByteArray(SAM_SERIAL_NUMBER), HexUtil.toByteArray(SAM_CHALLENGE)))
        .thenReturn(HexUtil.toByteArray(UNLOCK_DATA_DYNAMIC));

    samSelectionExtension.prepareReadSystemKeyParameters(SystemKeyType.PERSONALIZATION);
    samSelectionExtension.setDynamicUnlockDataProvider(dynamicUnlockDataProvider, samReader);
    samSelectionExtension.getCardSelectionRequest();
    /* TODO check this    samSelectionExtension.parse(cardSelectionResponseApi);

       InOrder inOrder = inOrder(dynamicUnlockDataProvider, samReader);
       inOrder
           .verify(dynamicUnlockDataProvider)
           .getUnlockData(HexUtil.toByteArray(SAM_SERIAL_NUMBER), HexUtil.toByteArray(SAM_CHALLENGE));
       inOrder
           .verify(samReader)
           .transmitCardRequest(
               argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
       verifyNoMoreInteractions(dynamicUnlockDataProvider, samReader);
    */
  }
}
