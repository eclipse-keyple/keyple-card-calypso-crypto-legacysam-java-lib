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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.List;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySam;
import org.eclipse.keypop.card.ApduResponseApi;
import org.eclipse.keypop.card.CardResponseApi;
import org.eclipse.keypop.card.CardSelectionResponseApi;
import org.eclipse.keypop.card.ParseException;
import org.junit.Before;
import org.junit.Test;

public final class LegacySamSelectionExtensionAdapterTest {

  private static final String SAM_ATR = "3B3F9600805AAABBC1DDEEFF11223344829000";
  private LegacySamSelectionExtensionAdapter samSelectionExtension;

  @Before
  public void setUp() {
    samSelectionExtension =
        (LegacySamSelectionExtensionAdapter)
            LegacySamExtensionService.getInstance()
                .getLegacySamApiFactory()
                .createLegacySamSelectionExtension();
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
  public void setUnlockData_whenUnlockDataIsInvalide_shouldThrowIAE() {
    samSelectionExtension.setUnlockData("00112233445566778899AABBCCDDEEGG");
  }

  @Test
  public void setUnlockData_whenUnlockData_shouldProduceUnlockDataApdu() {
    samSelectionExtension.setUnlockData("00112233445566778899AABBCCDDEEFF");
    byte[] unlockDataApdu =
        samSelectionExtension
            .getCardSelectionRequest()
            .getCardRequest()
            .getApduRequests()
            .get(0)
            .getApdu();
    assertThat(unlockDataApdu)
        .isEqualTo(HexUtil.toByteArray("802000001000112233445566778899AABBCCDDEEFF"));
  }

  @Test(expected = ParseException.class)
  public void parse_whenCommandsResponsesMismatch_shouldThrowIDE() throws Exception {
    CardSelectionResponseApi cardSelectionResponseApi = mock(CardSelectionResponseApi.class);
    when(cardSelectionResponseApi.getPowerOnData()).thenReturn(SAM_ATR);
    samSelectionExtension.setUnlockData("00112233445566778899AABBCCDDEEFF");
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
    samSelectionExtension.setUnlockData("00112233445566778899AABBCCDDEEFF");
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
    when(unlockApduResponse.getApdu()).thenReturn(HexUtil.toByteArray("9000"));
    when(unlockApduResponse.getStatusWord()).thenReturn(0x9000);
    when(cardSelectionResponseApi.getSelectApplicationResponse()).thenReturn(unlockApduResponse);
    when(cardSelectionResponseApi.getCardResponse()).thenReturn(cardResponseApi);
    when(cardResponseApi.getApduResponses()).thenReturn(apduResponseApis);
    samSelectionExtension.setUnlockData("00112233445566778899AABBCCDDEEFF");
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
}
