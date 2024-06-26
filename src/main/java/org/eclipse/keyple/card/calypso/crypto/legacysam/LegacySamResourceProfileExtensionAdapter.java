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

import org.eclipse.keyple.core.service.resource.spi.CardResourceProfileExtension;
import org.eclipse.keypop.calypso.crypto.legacysam.sam.LegacySamSelectionExtension;
import org.eclipse.keypop.reader.CardReader;
import org.eclipse.keypop.reader.ReaderApiFactory;
import org.eclipse.keypop.reader.selection.BasicCardSelector;
import org.eclipse.keypop.reader.selection.CardSelectionManager;
import org.eclipse.keypop.reader.selection.CardSelectionResult;
import org.eclipse.keypop.reader.selection.spi.SmartCard;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapter of {@link CardResourceProfileExtension} dedicated to SAM identification.
 *
 * @since 0.1.0
 */
class LegacySamResourceProfileExtensionAdapter implements CardResourceProfileExtension {

  private static final Logger logger =
      LoggerFactory.getLogger(LegacySamResourceProfileExtensionAdapter.class);

  private final LegacySamSelectionExtensionAdapter legacySamSelectionExtension;
  private final String powerOnDataRegex;

  /**
   * @param samSelectionExtension The {@link LegacySamSelectionExtension}.
   * @since 0.1.0
   */
  LegacySamResourceProfileExtensionAdapter(
      LegacySamSelectionExtensionAdapter samSelectionExtension, String powerOnDataRegex) {
    this.legacySamSelectionExtension = samSelectionExtension;
    this.powerOnDataRegex = powerOnDataRegex;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public SmartCard matches(CardReader reader, ReaderApiFactory readerApiFactory) {

    if (!reader.isCardPresent()) {
      return null;
    }
    BasicCardSelector cardSelector = readerApiFactory.createBasicCardSelector();
    if (powerOnDataRegex != null) {
      cardSelector.filterByPowerOnData(powerOnDataRegex);
    }
    CardSelectionManager samCardSelectionManager = readerApiFactory.createCardSelectionManager();
    legacySamSelectionExtension.setSamReader(reader);
    samCardSelectionManager.prepareSelection(cardSelector, legacySamSelectionExtension);
    CardSelectionResult samCardSelectionResult = null;
    try {
      samCardSelectionResult = samCardSelectionManager.processCardSelectionScenario(reader);
    } catch (Exception e) {
      logger.error("SAM selection failed: {}", e.getMessage(), e);
    }

    if (samCardSelectionResult != null) {
      return samCardSelectionResult.getActiveSmartCard();
    }

    return null;
  }
}
