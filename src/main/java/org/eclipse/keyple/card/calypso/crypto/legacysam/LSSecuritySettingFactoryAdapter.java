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

import org.calypsonet.terminal.calypso.crypto.legacysam.transaction.LSSecuritySetting;
import org.calypsonet.terminal.calypso.crypto.legacysam.transaction.LSSecuritySettingFactory;

/**
 * Implementation of {@link LSSecuritySettingFactory}.
 *
 * @since 0.3.0
 */
class LSSecuritySettingFactoryAdapter implements LSSecuritySettingFactory {

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  public LSSecuritySetting createSecuritySetting() {
    return new LSSecuritySettingAdapter();
  }
}
