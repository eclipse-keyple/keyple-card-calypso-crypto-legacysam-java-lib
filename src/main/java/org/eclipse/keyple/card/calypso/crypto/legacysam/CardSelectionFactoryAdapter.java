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

import org.calypsonet.terminal.calypso.crypto.legacysam.sam.CardSelectionFactory;
import org.calypsonet.terminal.calypso.crypto.legacysam.sam.LegacySamSelection;

/**
 * Adapter of {@link CardSelectionFactory}.
 *
 * @since 0.1.0
 */
class CardSelectionFactoryAdapter implements CardSelectionFactory {

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public LegacySamSelection createSamSelection() {
    return new LegacySamSelectionAdapter();
  }
}
