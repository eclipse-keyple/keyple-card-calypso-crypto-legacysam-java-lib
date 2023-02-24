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

import org.calypsonet.terminal.calypso.crypto.legacysam.sam.LegacySam;
import org.calypsonet.terminal.calypso.crypto.legacysam.transaction.LSSecuritySetting;
import org.calypsonet.terminal.card.ProxyReaderApi;
import org.calypsonet.terminal.reader.CardReader;
import org.eclipse.keyple.core.util.Assert;

/**
 * Implementation of {@link LSSecuritySettingAdapter}.
 *
 * @since 0.3.0
 */
final class LSSecuritySettingAdapter implements LSSecuritySetting {
  private ProxyReaderApi controlSamReader;
  private LegacySamAdapter controlSam;

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  public LSSecuritySetting setControlSamResource(CardReader samReader, LegacySam controlSam) {
    Assert.getInstance()
        .notNull(samReader, "samReader")
        .notNull(controlSam, "controlSam")
        .notNull(controlSam.getProductType(), "productType")
        .isTrue(controlSam.getProductType() != LegacySam.ProductType.UNKNOWN, "productType");
    controlSamReader = (ProxyReaderApi) samReader;
    this.controlSam = (LegacySamAdapter) controlSam;
    return this;
  }

  /**
   * Gets the associated control SAM reader to use for secured operations.
   *
   * @return Null if no control SAM reader is set.
   * @since 0.3.0
   */
  ProxyReaderApi getControlSamReader() {
    return controlSamReader;
  }

  /**
   * Gets the control SAM used for secured operations.
   *
   * @return Null if no control SAM is set.
   * @since 0.3.0
   */
  LegacySamAdapter getControlSam() {
    return controlSam;
  }
}
