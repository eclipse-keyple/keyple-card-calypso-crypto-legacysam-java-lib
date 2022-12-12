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

import org.calypsonet.terminal.calypso.crypto.legacysam.sam.LegacySamSelection;
import org.eclipse.keyple.core.service.resource.spi.CardResourceProfileExtension;
import org.eclipse.keyple.core.util.Assert;

/**
 * Provides an adapter of {@link CardResourceProfileExtension} to be used with the card resource
 * service.
 *
 * @since 0.1.0
 */
public final class LegacySamResourceProfileExtensionProvider {

  private LegacySamResourceProfileExtensionProvider() {}

  /**
   * Returns a {@link CardResourceProfileExtension}.
   *
   * @param samSelection The legacy SAM selection to use.
   * @return A not null reference.
   * @throws IllegalArgumentException If no SAM selection is provided.
   * @since 0.1.0
   */
  public static CardResourceProfileExtension getSamProfileExtension(
      LegacySamSelection samSelection) {
    Assert.getInstance().notNull(samSelection, "SAM selection");
    return new LegacySamResourceProfileExtensionAdapter(samSelection);
  }
}
