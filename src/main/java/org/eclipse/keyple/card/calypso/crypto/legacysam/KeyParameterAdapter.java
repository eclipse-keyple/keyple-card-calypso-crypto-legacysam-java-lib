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

import org.calypsonet.terminal.calypso.crypto.legacysam.sam.KeyParameter;
import org.eclipse.keyple.core.util.Assert;

/**
 * Implementation of {@link KeyParameter}.
 *
 * @since 0.3.0
 */
final class KeyParameterAdapter implements KeyParameter {
  private final byte[] keyParameters;

  KeyParameterAdapter(byte[] keyParameters) {
    this.keyParameters = keyParameters;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  public byte[] getRawData() {
    return keyParameters;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  public byte getKif() {
    return keyParameters[0];
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  public byte getKvc() {
    return keyParameters[1];
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  public byte getAlgorithm() {
    return keyParameters[2];
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  public byte getParameterValue(int parameterNumber) {
    Assert.getInstance().isInRange(parameterNumber, 1, 10, "parameterNumber");
    return keyParameters[2 + parameterNumber];
  }
}
