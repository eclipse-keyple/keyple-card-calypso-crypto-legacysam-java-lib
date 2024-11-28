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
final class LegacySamResourceProfileExtensionAdapter implements CardResourceProfileExtension {

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

    // Is SAM inserted?
    if (!reader.isCardPresent()) {
      return null;
    }

    // Init the SAM selector
    BasicCardSelector cardSelector = readerApiFactory.createBasicCardSelector();
    if (powerOnDataRegex != null) {
      cardSelector.filterByPowerOnData(powerOnDataRegex);
    }

    // Associate the provided reader to the prepared LegacySAM selection extension and prepare an
    // additional "Get Challenge" command for network optimization.
    legacySamSelectionExtension.setSamReader(reader);
    legacySamSelectionExtension.prepareGetChallengeIfNeeded();

    // Prepare the SAM selection scenario
    CardSelectionManager samCardSelectionManager = readerApiFactory.createCardSelectionManager();
    samCardSelectionManager.prepareSelection(cardSelector, legacySamSelectionExtension);

    // Process the SAM selection scenario
    CardSelectionResult samCardSelectionResult = null;
    try {
      samCardSelectionResult = samCardSelectionManager.processCardSelectionScenario(reader);
    } catch (Exception e) {
      logger.error("SAM selection failed: {}", e.getMessage(), e);
    }

    return samCardSelectionResult != null ? samCardSelectionResult.getActiveSmartCard() : null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.8.0
   */
  @Override
  public SmartCard matches(SmartCard smartCard) {
    if (!(smartCard instanceof LegacySamAdapter)) {
      return null;
    }
    if (powerOnDataRegex != null && !smartCard.getPowerOnData().matches(powerOnDataRegex)) {
      return null;
    }
    return smartCard;
  }
}
