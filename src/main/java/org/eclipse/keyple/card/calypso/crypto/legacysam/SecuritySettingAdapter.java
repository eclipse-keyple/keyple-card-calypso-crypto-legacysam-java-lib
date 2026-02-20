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

import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySam;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.SecuritySetting;
import org.eclipse.keypop.card.ProxyReaderApi;
import org.eclipse.keypop.reader.CardReader;

/**
 * Implementation of {@link SecuritySettingAdapter}.
 *
 * @since 0.3.0
 */
final class SecuritySettingAdapter implements SecuritySetting {
  private ProxyReaderApi controlSamReader;
  private LegacySamAdapter controlSam;

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  public SecuritySetting setControlSamResource(CardReader samReader, LegacySam controlSam) {
    Assert.getInstance()
        .notNull(samReader, "samReader")
        .notNull(controlSam, "controlSam")
        .notNull(controlSam.getProductType(), "productType")
        .isTrue(controlSam.getProductType() != LegacySam.ProductType.UNKNOWN, "productType");
    if (!(samReader instanceof ProxyReaderApi)) {
      throw new IllegalArgumentException(
          "Cannot cast 'samReader' to ProxyReaderApi. Actual type: "
              + samReader.getClass().getName());
    }
    if (!(controlSam instanceof LegacySamAdapter)) {
      throw new IllegalArgumentException(
          "Cannot cast 'controlSam' to LegacySamAdapter. Actual type: "
              + controlSam.getClass().getName());
    }
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
