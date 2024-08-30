/* **************************************************************************************
 * Copyright (c) 2024 Calypso Networks Association https://calypsonet.org/
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

import org.eclipse.keypop.calypso.crypto.legacysam.CounterIncrementAccess;
import org.eclipse.keypop.calypso.crypto.legacysam.SystemKeyType;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.SecureWriteTransactionManager;
import org.eclipse.keypop.card.ProxyReaderApi;

/**
 * Adapter of {@link SecureWriteTransactionManager}.
 *
 * @since 0.7.0
 */
public class SecureWriteTransactionManagerAdapter extends CommonTransactionManagerAdapter
    implements SecureWriteTransactionManager {

  /**
   * Constructor
   *
   * @param targetSamReader The reader through which the target SAM communicates.
   * @param targetSam The target legacy SAM.
   * @param controlSamReader The reader through which the control SAM communicates.
   * @param controlSam The control legacy SAM.
   */
  SecureWriteTransactionManagerAdapter(
      ProxyReaderApi targetSamReader,
      LegacySamAdapter targetSam,
      ProxyReaderApi controlSamReader,
      LegacySamAdapter controlSam) {
    super(targetSamReader, targetSam, controlSamReader, controlSam);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.7.0
   */
  @Override
  public SecureWriteTransactionManager prepareWriteSamParameters(byte[] parameters) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.7.0
   */
  @Override
  public SecureWriteTransactionManager prepareTransferSystemKey(
      SystemKeyType systemKeyType, byte[] systemKeyParameters) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.7.0
   */
  @Override
  public SecureWriteTransactionManager prepareTransferWorkKey(
      byte kif, byte kvc, byte[] workKeyParameters, int recordNumber) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.7.0
   */
  @Override
  public SecureWriteTransactionManager prepareWriteCounterCeiling(
      int counterNumber, int ceilingValue) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.7.0
   */
  @Override
  public SecureWriteTransactionManager prepareWriteCounterConfiguration(
      int counterNumber, int ceilingValue, CounterIncrementAccess counterIncrementAccess) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.7.0
   */
  @Override
  public SecureWriteTransactionManager processCommands() {
    processTargetSamCommands(false);
    return this;
  }
}
