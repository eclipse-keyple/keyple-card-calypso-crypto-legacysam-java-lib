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

/**
 * Adapter of {@link ContextSetting}.
 *
 * @since 0.4.0
 */
final class ContextSettingAdapter implements ContextSetting {

  private Integer contactReaderPayloadCapacity;

  /**
   * {@inheritDoc}
   *
   * @since 0.4.0
   */
  @Override
  public ContextSetting setContactReaderPayloadCapacity(int payloadCapacity) {
    Assert.getInstance().isInRange(payloadCapacity, 0, 255, "payloadCapacity");
    this.contactReaderPayloadCapacity = payloadCapacity;
    return this;
  }

  /**
   * Returns the contact reader payload capacity.
   *
   * @return null if no payload capacity has been defined.
   * @since 0.4.0
   */
  Integer getContactReaderPayloadCapacity() {
    return contactReaderPayloadCapacity;
  }
}
