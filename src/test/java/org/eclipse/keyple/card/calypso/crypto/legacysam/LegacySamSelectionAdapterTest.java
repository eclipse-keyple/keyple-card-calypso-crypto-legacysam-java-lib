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
import static org.calypsonet.terminal.calypso.crypto.legacysam.sam.LegacySam.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.List;
import org.calypsonet.terminal.calypso.crypto.legacysam.sam.LegacySam;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.calypsonet.terminal.card.CardResponseApi;
import org.calypsonet.terminal.card.CardSelectionResponseApi;
import org.calypsonet.terminal.card.spi.CardSelectorSpi;
import org.calypsonet.terminal.card.spi.ParseException;
import org.eclipse.keyple.core.util.HexUtil;
import org.junit.Before;
import org.junit.Test;

public class LegacySamSelectionAdapterTest {

  public static final String SAM_ATR = "3B3F9600805AAABBC1DDEEFF11223344829000";
  private LegacySamSelectionAdapter samSelection;

  @Before
  public void setUp() {
    samSelection =
        (LegacySamSelectionAdapter)
            LegacySamCardExtensionService.getInstance()
                .getLegacySamSelectionFactory()
                .createSamSelection();
  }

  @Test(expected = IllegalArgumentException.class)
  public void filterByProductType_whenProductTypeIsNull_shouldThrowIAE() {
    samSelection.filterByProductType(null);
  }

  @Test
  public void
      filterByProductType_whenProductTypeIsNotDefined_shouldReturnResponseContainingACardSelectorWithPowerDataRegexAllowingAnyType() {
    CardSelectorSpi cardSelector = samSelection.getCardSelectionRequest().getCardSelector();
    assertThat(cardSelector.getPowerOnDataRegex()).isEqualTo(".*");
  }

  @Test
  public void
      filterByProductType_whenProductTypeIsDefined_shouldReturnResponseContainingACardSelectorWithPowerDataRegex() {
    samSelection.filterByProductType(ProductType.SAM_C1);
    CardSelectorSpi cardSelector = samSelection.getCardSelectionRequest().getCardSelector();
    assertThat(cardSelector.getPowerOnDataRegex()).contains("80C1.{6}");
  }

  @Test(expected = IllegalArgumentException.class)
  public void filterBySerialNumber_whenSerialNumberRegexIsNull_shouldThrowIAE() {
    samSelection.filterBySerialNumber(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void filterBySerialNumber_whenSerialNumberRegexIsInvalid_shouldThrowIAE() {
    samSelection.filterBySerialNumber("[");
  }

  @Test
  public void filterBySerialNumber_shouldReturnResponseContainingACardSelectorWithPowerDataRegex() {
    samSelection.filterByProductType(ProductType.SAM_C1).filterBySerialNumber("112233..");
    CardSelectorSpi cardSelector = samSelection.getCardSelectionRequest().getCardSelector();
    assertThat(cardSelector.getPowerOnDataRegex()).contains("112233..");
  }

  @Test(expected = IllegalArgumentException.class)
  public void setUnlockData_whenUnlockDataIsNull_shouldThrowIAE() {
    samSelection.setUnlockData(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void setUnlockData_whenUnlockDataHasABadLength_shouldThrowIAE() {
    samSelection.setUnlockData("00112233445566778899AABBCCDDEE");
  }

  @Test(expected = IllegalArgumentException.class)
  public void setUnlockData_whenUnlockDataIsInvalide_shouldThrowIAE() {
    samSelection.setUnlockData("00112233445566778899AABBCCDDEEGG");
  }

  @Test
  public void setUnlockData_whenUnlockData_shouldProduceUnlockDataApdu() {
    samSelection.setUnlockData("00112233445566778899AABBCCDDEEFF");
    byte[] unlockDataApdu =
        samSelection.getCardSelectionRequest().getCardRequest().getApduRequests().get(0).getApdu();
    assertThat(unlockDataApdu)
        .isEqualTo(HexUtil.toByteArray("802000001000112233445566778899AABBCCDDEEFF"));
  }

  @Test(expected = ParseException.class)
  public void parse_whenCommandsResponsesMismatch_shouldThrowIDE() throws Exception {
    CardSelectionResponseApi cardSelectionResponseApi = mock(CardSelectionResponseApi.class);
    when(cardSelectionResponseApi.getPowerOnData()).thenReturn(SAM_ATR);
    samSelection.setUnlockData("00112233445566778899AABBCCDDEEFF");
    samSelection.getCardSelectionRequest();
    samSelection.parse(cardSelectionResponseApi);
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
    samSelection.setUnlockData("00112233445566778899AABBCCDDEEFF");
    samSelection.getCardSelectionRequest();
    samSelection.parse(cardSelectionResponseApi);
  }

  @Test
  public void parse_whenUnlockSucceed_shouldReturnLegacySam() throws Exception {
    CardSelectionResponseApi cardSelectionResponseApi = mock(CardSelectionResponseApi.class);
    CardResponseApi cardResponseApi = mock(CardResponseApi.class);
    when(cardSelectionResponseApi.getPowerOnData()).thenReturn(SAM_ATR);
    ApduResponseApi unlockApduResponse = mock(ApduResponseApi.class);
    List<ApduResponseApi> apduResponseApis = Collections.singletonList(unlockApduResponse);
    when(unlockApduResponse.getApdu()).thenReturn(HexUtil.toByteArray("9000"));
    when(unlockApduResponse.getStatusWord()).thenReturn(0x9000);
    when(cardSelectionResponseApi.getSelectApplicationResponse()).thenReturn(unlockApduResponse);
    when(cardSelectionResponseApi.getCardResponse()).thenReturn(cardResponseApi);
    when(cardResponseApi.getApduResponses()).thenReturn(apduResponseApis);
    samSelection.filterByProductType(ProductType.SAM_C1);
    samSelection.setUnlockData("00112233445566778899AABBCCDDEEFF");
    samSelection.getCardSelectionRequest();
    LegacySam LegacySam = (LegacySam) samSelection.parse(cardSelectionResponseApi);
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
}
