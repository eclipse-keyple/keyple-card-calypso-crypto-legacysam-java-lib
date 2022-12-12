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

import org.calypsonet.terminal.calypso.crypto.legacysam.transaction.LSCommandDataFactory;

/**
 * Provides an adapter of {@link LSCommandDataFactory}.
 *
 * @since 0.1.0
 */
public final class LSCommandDataFactoryProvider {

  private LSCommandDataFactoryProvider() {}

  /**
   * Returns a {@link LSCommandDataFactory}.
   *
   * @return A not null reference.
   * @since 0.1.0
   */
  public static LSCommandDataFactory getFactory() {
    return new LSCommandDataFactoryAdapter();
  }
}
