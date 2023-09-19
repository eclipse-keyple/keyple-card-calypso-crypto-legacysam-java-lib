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

import java.util.List;
import org.eclipse.keypop.calypso.card.transaction.spi.SymmetricCryptoTransactionManagerFactory;
import org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySam;
import org.eclipse.keypop.calypso.crypto.symmetric.spi.SymmetricCryptoTransactionManagerFactorySpi;
import org.eclipse.keypop.calypso.crypto.symmetric.spi.SymmetricCryptoTransactionManagerSpi;
import org.eclipse.keypop.card.ProxyReaderApi;

/**
 * Adapter of {@link SymmetricCryptoTransactionManagerFactory}.
 *
 * @since 0.4.0
 */
class SymmetricCryptoTransactionManagerFactoryAdapter
    implements SymmetricCryptoTransactionManagerFactory,
        SymmetricCryptoTransactionManagerFactorySpi {

  private final ProxyReaderApi samReader;
  private final LegacySamAdapter sam;
  private final boolean isExtendedModeSupported;
  private final int maxCardApduLengthSupported;

  SymmetricCryptoTransactionManagerFactoryAdapter(
      ProxyReaderApi samReader, LegacySamAdapter sam, ContextSettingAdapter contextSetting) {
    this.samReader = samReader;
    this.sam = sam;
    this.isExtendedModeSupported =
        sam.getProductType() == LegacySam.ProductType.SAM_C1
            || sam.getProductType() == LegacySam.ProductType.HSM_C1;
    this.maxCardApduLengthSupported =
        contextSetting.getContactReaderPayloadCapacity() != null
            ? Math.min(
                sam.getMaxDigestDataLength(), contextSetting.getContactReaderPayloadCapacity())
            : sam.getMaxDigestDataLength();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public boolean isExtendedModeSupported() {
    return isExtendedModeSupported;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public int getMaxCardApduLengthSupported() {
    return maxCardApduLengthSupported;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public SymmetricCryptoTransactionManagerSpi createTransactionManager(
      byte[] cardKeyDiversifier, boolean useExtendedMode, List<byte[]> transactionAuditData) {
    if (useExtendedMode && !isExtendedModeSupported) {
      throw new IllegalStateException("The extended mode is not supported by the crypto service");
    }
    return new SymmetricCryptoTransactionManagerAdapter(
        samReader,
        sam,
        cardKeyDiversifier,
        useExtendedMode,
        maxCardApduLengthSupported,
        transactionAuditData);
  }
}
