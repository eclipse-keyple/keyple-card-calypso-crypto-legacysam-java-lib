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
import org.eclipse.keypop.calypso.crypto.legacysam.LegacySamApiFactory;
import org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySam;
import org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySamSelectionExtension;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.*;
import org.eclipse.keypop.card.ProxyReaderApi;
import org.eclipse.keypop.reader.CardReader;

/**
 * Adapter of {@link LegacySamApiFactory}.
 *
 * @since 1.0.0
 */
public class LegacySamApiFactoryAdapter implements LegacySamApiFactory {
  /**
   * {@inheritDoc}
   *
   * @since 1.0.0
   */
  @Override
  public LegacySamSelectionExtension createLegacySamSelectionExtension() {
    return new LegacySamSelectionExtensionAdapter();
  }

  /**
   * {@inheritDoc}
   *
   * @since 1.0.0
   */
  @Override
  public SecuritySetting createSecuritySetting() {
    return new SecuritySettingAdapter();
  }

  /**
   * {@inheritDoc}
   *
   * @since 1.0.0
   */
  @Override
  public FreeTransactionManager createFreeTransactionManager(CardReader samReader, LegacySam sam) {

    if (!(samReader instanceof ProxyReaderApi)) {
      throw new IllegalArgumentException(
          "The provided 'samReader' must implement 'ProxyReaderApi'");
    }
    if (!(sam instanceof LegacySamAdapter)) {
      throw new IllegalArgumentException(
          "The provided 'sam' must be an instance of 'LegacySamAdapter'");
    }
    return new FreeTransactionManagerAdapter((ProxyReaderApi) samReader, (LegacySamAdapter) sam);
  }

  /**
   * {@inheritDoc}
   *
   * @since 1.0.0
   */
  @Override
  public AsyncTransactionCreatorManager createAsyncTransactionCreatorManager(
      String targetSamContext, SecuritySetting securitySetting) {
    Assert.getInstance()
        .notNull(targetSamContext, "targetSamContext")
        .notNull(securitySetting, "securitySetting");
    return new AsyncTransactionCreatorManagerAdapter(targetSamContext, securitySetting);
  }

  /**
   * {@inheritDoc}
   *
   * @since 1.0.0
   */
  @Override
  public AsyncTransactionExecutorManager createAsyncTransactionExecutorManager(
      CardReader samReader, LegacySam sam, String samCommands) {

    if (!(samReader instanceof ProxyReaderApi)) {
      throw new IllegalArgumentException(
          "The provided 'samReader' must implement 'ProxyReaderApi'");
    }
    if (!(sam instanceof LegacySamAdapter)) {
      throw new IllegalArgumentException(
          "The provided 'sam' must be an instance of 'LegacySamAdapter'");
    }
    Assert.getInstance().notNull(samCommands, "samCommands");
    return new AsyncTransactionExecutorManagerAdapter(
        (ProxyReaderApi) samReader, (LegacySamAdapter) sam, samCommands);
  }

  /**
   * {@inheritDoc}
   *
   * @since 1.0.0
   */
  @Override
  public BasicSignatureComputationData createBasicSignatureComputationData() {
    return new DtoAdapters.BasicSignatureComputationDataAdapter();
  }

  /**
   * {@inheritDoc}
   *
   * @since 1.0.0
   */
  @Override
  public TraceableSignatureComputationData createTraceableSignatureComputationData() {
    return new DtoAdapters.TraceableSignatureComputationDataAdapter();
  }

  /**
   * {@inheritDoc}
   *
   * @since 1.0.0
   */
  @Override
  public BasicSignatureVerificationData createBasicSignatureVerificationData() {
    return new DtoAdapters.BasicSignatureVerificationDataAdapter();
  }

  /**
   * {@inheritDoc}
   *
   * @since 1.0.0
   */
  @Override
  public TraceableSignatureVerificationData createTraceableSignatureVerificationData() {
    return new DtoAdapters.TraceableSignatureVerificationDataAdapter();
  }
}
