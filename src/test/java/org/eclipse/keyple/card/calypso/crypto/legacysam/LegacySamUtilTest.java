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

import static org.assertj.core.api.Assertions.*;
import static org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySam.ProductType.UNKNOWN;

import org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySam;
import org.junit.Test;

public class LegacySamUtilTest {

  @Test
  public void buildPowerOnDataFilter_whenSamC1_shouldBuildRightRegex() {
    String actual = LegacySamUtil.buildPowerOnDataFilter(LegacySam.ProductType.SAM_C1, "12345678");
    String expected = "3B(.{6}|.{10})805A..80C1.{6}12345678829000";
    assertThat(actual).isEqualTo(expected);
  }

  @Test
  public void buildPowerOnDataFilter_whenHsmC1_shouldBuildRightRegex() {
    String actual = LegacySamUtil.buildPowerOnDataFilter(LegacySam.ProductType.HSM_C1, "87654321");
    String expected = "3B(.{6}|.{10})805A..80C1.{6}87654321829000";
    assertThat(actual).isEqualTo(expected);
  }

  @Test
  public void buildPowerOnDataFilter_whenSamS1DX_shouldBuildRightRegex() {
    String actual =
        LegacySamUtil.buildPowerOnDataFilter(LegacySam.ProductType.SAM_S1DX, "ABCDEFGH");
    String expected = "3B(.{6}|.{10})805A..80D?.{6}ABCDEFGH829000";
    assertThat(actual).isEqualTo(expected);
  }

  @Test
  public void buildPowerOnDataFilter_whenSamS1E1_shouldBuildRightRegex() {
    String actual =
        LegacySamUtil.buildPowerOnDataFilter(LegacySam.ProductType.SAM_S1E1, "HGFEDCBA");
    String expected = "3B(.{6}|.{10})805A..80E1.{6}HGFEDCBA829000";
    assertThat(actual).isEqualTo(expected);
  }

  @Test(expected = IllegalArgumentException.class)
  public void buildPowerOnDataFilter_whenUnknownRegex_shouldIAE() {
    LegacySamUtil.buildPowerOnDataFilter(UNKNOWN, "HGFEDCBA");
  }

  @Test
  public void buildPowerOnDataFilter_whenNoSerialNumber_shouldBuildRightRegex() {
    String actual = LegacySamUtil.buildPowerOnDataFilter(LegacySam.ProductType.SAM_C1, null);
    String expected = "3B(.{6}|.{10})805A..80C1.{6}.{8}829000";
    assertThat(actual).isEqualTo(expected);
  }
}
