/* **************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/
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

import org.eclipse.keyple.core.common.CommonApiProperties;
import org.eclipse.keyple.core.common.KeypleCardExtension;
import org.eclipse.keyple.core.service.resource.spi.CardResourceProfileExtension;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keypop.calypso.crypto.legacysam.LegacySamApiFactory;
import org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySamSelectionExtension;
import org.eclipse.keypop.card.CardApiProperties;
import org.eclipse.keypop.reader.ReaderApiProperties;

/**
 * Card extension dedicated to the management of Calypso legacy SAMs (SAM-C1, HSM-C1, etc...).
 *
 * @since 0.2.0
 */
public final class LegacySamCardExtensionService implements KeypleCardExtension {

  /** Singleton */
  private static final LegacySamCardExtensionService INSTANCE = new LegacySamCardExtensionService();

  /** Private constructor */
  private LegacySamCardExtensionService() {}

  /**
   * Returns the service instance.
   *
   * @return A not null reference.
   * @since 0.2.0
   */
  public static LegacySamCardExtensionService getInstance() {
    return INSTANCE;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.2.0
   */
  @Override
  public String getReaderApiVersion() {
    return ReaderApiProperties.VERSION;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.2.0
   */
  @Override
  public String getCardApiVersion() {
    return CardApiProperties.VERSION;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.2.0
   */
  @Override
  public String getCommonApiVersion() {
    return CommonApiProperties.VERSION;
  }

  /**
   * Returns a {@link LegacySamApiFactory}.
   *
   * @return A not null reference.
   * @since 1.0.0
   */
  public LegacySamApiFactory getLegacySamApiFactory() {
    return new LegacySamApiFactoryAdapter();
  }

  /**
   * Returns a {@link CardResourceProfileExtension} to be used with the card resource service.
   *
   * @param legacySamSelection The legacy SAM selection extension to use.
   * @return A not null reference.
   * @throws IllegalArgumentException If no SAM selection is provided.
   * @since 0.2.0
   */
  public CardResourceProfileExtension createLegacySamResourceProfileExtension(
      LegacySamSelectionExtension legacySamSelection) {
    Assert.getInstance().notNull(legacySamSelection, "Legacy SAM selection");
    return new LegacySamResourceProfileExtensionAdapter(legacySamSelection, null);
  }

  /**
   * Returns a {@link CardResourceProfileExtension} to be used with the card resource service.
   *
   * @param legacySamSelection The legacy SAM selection extension to use.
   * @param powerOnDataRegex A regular expression.
   * @return A not null reference.
   * @throws IllegalArgumentException If no SAM selection is provided.
   * @throws IllegalArgumentException If the regular expression is null or empty.
   * @since 0.2.0
   */
  public CardResourceProfileExtension createLegacySamResourceProfileExtension(
      LegacySamSelectionExtension legacySamSelection, String powerOnDataRegex) {
    Assert.getInstance()
        .notNull(legacySamSelection, "Legacy SAM selection")
        .notEmpty(powerOnDataRegex, "powerOnDataRegex");
    return new LegacySamResourceProfileExtensionAdapter(legacySamSelection, powerOnDataRegex);
  }
}
