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

import static org.eclipse.keyple.card.calypso.crypto.legacysam.DtoAdapters.*;

import org.calypsonet.terminal.calypso.crypto.legacysam.transaction.*;

/**
 * Adapter of {@link LSCommandDataFactory}.
 *
 * @since 0.1.0
 */
final class LSCommandDataFactoryAdapter implements LSCommandDataFactory {

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public BasicSignatureComputationData createBasicSignatureComputationData() {
    return new BasicSignatureComputationDataAdapter();
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public TraceableSignatureComputationData createTraceableSignatureComputationData() {
    return new TraceableSignatureComputationDataAdapter();
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public BasicSignatureVerificationData createBasicSignatureVerificationData() {
    return new BasicSignatureVerificationDataAdapter();
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public TraceableSignatureVerificationData createTraceableSignatureVerificationData() {
    return new TraceableSignatureVerificationDataAdapter();
  }
}
