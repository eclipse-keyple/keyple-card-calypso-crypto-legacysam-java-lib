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

import java.util.*;
import org.calypsonet.terminal.calypso.crypto.legacysam.SystemKeyType;
import org.calypsonet.terminal.calypso.crypto.legacysam.transaction.*;
import org.calypsonet.terminal.card.ProxyReaderApi;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keyple.core.util.json.JsonUtil;

/**
 * Adapter of {@link LSFreeTransactionManager}.
 *
 * @since 0.1.0
 */
class LSFreeTransactionManagerAdapter extends CommonTransactionManagerAdapter
    implements LSFreeTransactionManager {
  private static final String MSG_INPUT_OUTPUT_DATA = "input/output data";
  private static final String MSG_SIGNATURE_SIZE = "signature size";
  private static final String MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8 =
      "key diversifier size is in range [1..8]";

  /* Final fields */
  private final byte[] samKeyDiversifier;

  /* Dynamic fields */
  private byte[] currentKeyDiversifier;

  LSFreeTransactionManagerAdapter(ProxyReaderApi samReader, LegacySamAdapter sam) {
    super(samReader, sam, null, null);
    this.samKeyDiversifier = sam.getSerialNumber();
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public LSFreeTransactionManager prepareComputeSignature(CommonSignatureComputationData<?> data) {

    if (data instanceof BasicSignatureComputationDataAdapter) {
      // Basic signature
      BasicSignatureComputationDataAdapter dataAdapter =
          (BasicSignatureComputationDataAdapter) data;

      Assert.getInstance()
          .notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
          .notNull(dataAdapter.getData(), "data to sign")
          .isInRange(dataAdapter.getData().length, 1, 208, "length of data to sign")
          .isTrue(
              dataAdapter.getData().length % 8 == 0, "length of data to sign is a multiple of 8")
          .isInRange(dataAdapter.getSignatureSize(), 1, 8, MSG_SIGNATURE_SIZE)
          .isTrue(
              dataAdapter.getKeyDiversifier() == null
                  || (dataAdapter.getKeyDiversifier().length >= 1
                      && dataAdapter.getKeyDiversifier().length <= 8),
              MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

      prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
      addTargetSamCommand(new CommandDataCipher(getContext(), dataAdapter, null));

    } else if (data instanceof TraceableSignatureComputationDataAdapter) {
      // Traceable signature
      TraceableSignatureComputationDataAdapter dataAdapter =
          (TraceableSignatureComputationDataAdapter) data;

      Assert.getInstance()
          .notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
          .notNull(dataAdapter.getData(), "data to sign")
          .isInRange(
              dataAdapter.getData().length,
              1,
              dataAdapter.isSamTraceabilityMode() ? 206 : 208,
              "length of data to sign")
          .isInRange(dataAdapter.getSignatureSize(), 1, 8, MSG_SIGNATURE_SIZE)
          .isTrue(
              !dataAdapter.isSamTraceabilityMode()
                  || (dataAdapter.getTraceabilityOffset() >= 0
                      && dataAdapter.getTraceabilityOffset()
                          <= ((dataAdapter.getData().length * 8)
                              - (dataAdapter.isPartialSamSerialNumber() ? 7 * 8 : 8 * 8))),
              "traceability offset is in range [0.."
                  + ((dataAdapter.getData().length * 8)
                      - (dataAdapter.isPartialSamSerialNumber() ? 7 * 8 : 8 * 8))
                  + "]")
          .isTrue(
              dataAdapter.getKeyDiversifier() == null
                  || (dataAdapter.getKeyDiversifier().length >= 1
                      && dataAdapter.getKeyDiversifier().length <= 8),
              MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

      prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
      addTargetSamCommand(new CommandPsoComputeSignature(getContext(), dataAdapter));

    } else {
      throw new IllegalArgumentException(
          "The provided data must be an instance of 'BasicSignatureComputationDataAdapter' or 'TraceableSignatureComputationDataAdapter'");
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public LSFreeTransactionManager prepareVerifySignature(CommonSignatureVerificationData<?> data) {
    if (data instanceof BasicSignatureVerificationDataAdapter) {
      // Basic signature
      BasicSignatureVerificationDataAdapter dataAdapter =
          (BasicSignatureVerificationDataAdapter) data;

      Assert.getInstance()
          .notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
          .notNull(dataAdapter.getData(), "signed data to verify")
          .isInRange(dataAdapter.getData().length, 1, 208, "length of signed data to verify")
          .isTrue(
              dataAdapter.getData().length % 8 == 0, "length of data to verify is a multiple of 8")
          .notNull(dataAdapter.getSignature(), "signature")
          .isInRange(dataAdapter.getSignature().length, 1, 8, MSG_SIGNATURE_SIZE)
          .isTrue(
              dataAdapter.getKeyDiversifier() == null
                  || (dataAdapter.getKeyDiversifier().length >= 1
                      && dataAdapter.getKeyDiversifier().length <= 8),
              MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

      prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
      addTargetSamCommand(new CommandDataCipher(getContext(), null, dataAdapter));

    } else if (data instanceof TraceableSignatureVerificationDataAdapter) {
      // Traceable signature
      TraceableSignatureVerificationDataAdapter dataAdapter =
          (TraceableSignatureVerificationDataAdapter) data;

      Assert.getInstance()
          .notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
          .notNull(dataAdapter.getData(), "signed data to verify")
          .isInRange(
              dataAdapter.getData().length,
              1,
              dataAdapter.isSamTraceabilityMode() ? 206 : 208,
              "length of signed data to verify")
          .notNull(dataAdapter.getSignature(), "signature")
          .isInRange(dataAdapter.getSignature().length, 1, 8, MSG_SIGNATURE_SIZE)
          .isTrue(
              !dataAdapter.isSamTraceabilityMode()
                  || (dataAdapter.getTraceabilityOffset() >= 0
                      && dataAdapter.getTraceabilityOffset()
                          <= ((dataAdapter.getData().length * 8)
                              - (dataAdapter.isPartialSamSerialNumber() ? 7 * 8 : 8 * 8))),
              "traceability offset is in range [0.."
                  + ((dataAdapter.getData().length * 8)
                      - (dataAdapter.isPartialSamSerialNumber() ? 7 * 8 : 8 * 8))
                  + "]")
          .isTrue(
              dataAdapter.getKeyDiversifier() == null
                  || (dataAdapter.getKeyDiversifier().length >= 1
                      && dataAdapter.getKeyDiversifier().length <= 8),
              MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

      // Check SAM revocation status if requested.
      if (dataAdapter.getSamRevocationService() != null) {
        // Extract the SAM serial number and the counter value from the data.
        byte[] samSerialNumber =
            ByteArrayUtil.extractBytes(
                dataAdapter.getData(),
                dataAdapter.getTraceabilityOffset(),
                dataAdapter.isPartialSamSerialNumber() ? 3 : 4);

        int samCounterValue =
            ByteArrayUtil.extractInt(
                ByteArrayUtil.extractBytes(
                    dataAdapter.getData(),
                    dataAdapter.getTraceabilityOffset()
                        + (dataAdapter.isPartialSamSerialNumber() ? 3 * 8 : 4 * 8),
                    3),
                0,
                3,
                false);

        // Is SAM revoked ?
        if (dataAdapter.getSamRevocationService().isSamRevoked(samSerialNumber, samCounterValue)) {
          throw new SamRevokedException(
              String.format(
                  "SAM with serial number '%s' and counter value '%d' is revoked.",
                  HexUtil.toHex(samSerialNumber), samCounterValue));
        }
      }

      prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
      addTargetSamCommand(new CommandPsoVerifySignature(getContext(), dataAdapter));

    } else {
      throw new IllegalArgumentException(
          "The provided data must be an instance of 'CommonSignatureVerificationDataAdapter'");
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  public LSFreeTransactionManager prepareReadSystemKeyParameters(SystemKeyType systemKeyType) {
    Assert.getInstance().notNull(systemKeyType, "systemKeyType");
    addTargetSamCommand(new CommandReadKeyParameters(getContext(), systemKeyType));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public LSFreeTransactionManager prepareReadCounterStatus(int counterNumber) {
    Assert.getInstance()
        .isInRange(counterNumber, MIN_COUNTER_NUMBER, MAX_COUNTER_NUMBER, "counterNumber");
    for (Command command : getTargetSamCommands()) {
      if (command instanceof CommandReadCounter
          && ((CommandReadCounter) command).getCounterFileRecordNumber()
              == counterToRecordLookup[counterNumber]) {
        // already scheduled
        return this;
      }
    }
    addTargetSamCommand(new CommandReadCounter(getContext(), counterToRecordLookup[counterNumber]));
    addTargetSamCommand(
        new CommandReadCounterCeiling(getContext(), counterToRecordLookup[counterNumber]));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public LSFreeTransactionManager prepareReadAllCountersStatus() {
    for (int i = 0; i < 3; i++) {
      addTargetSamCommand(new CommandReadCounter(getContext(), i));
      addTargetSamCommand(new CommandReadCounterCeiling(getContext(), i));
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  public String exportTargetSamContextForAsyncTransaction() {

    final List<Command> commands = new ArrayList<Command>();

    // read system key parameters if not available
    if (getContext().getTargetSam().getSystemKeyParameter(SystemKeyType.PERSONALIZATION) == null) {
      commands.add(new CommandReadKeyParameters(getContext(), SystemKeyType.PERSONALIZATION));
    }
    if (getContext().getTargetSam().getSystemKeyParameter(SystemKeyType.KEY_MANAGEMENT) == null) {
      commands.add(new CommandReadKeyParameters(getContext(), SystemKeyType.KEY_MANAGEMENT));
    }
    if (getContext().getTargetSam().getSystemKeyParameter(SystemKeyType.RELOADING) == null) {
      commands.add(new CommandReadKeyParameters(getContext(), SystemKeyType.RELOADING));
    }
    processTargetSamCommands(commands);
    commands.clear();

    // read PAR4
    int counterPersonalization =
        getContext()
                .getTargetSam()
                .getSystemKeyParameter(SystemKeyType.PERSONALIZATION)
                .getParameterValue(4)
            & 0xFF;
    int counterKeyManagement =
        getContext()
                .getTargetSam()
                .getSystemKeyParameter(SystemKeyType.KEY_MANAGEMENT)
                .getParameterValue(4)
            & 0xFF;
    int counterReloading =
        getContext()
                .getTargetSam()
                .getSystemKeyParameter(SystemKeyType.RELOADING)
                .getParameterValue(4)
            & 0xFF;

    TargetSamContextDto targetSamContextDto =
        new TargetSamContextDto(getContext().getTargetSam().getSerialNumber(), false);
    if (counterPersonalization != 0) {
      targetSamContextDto
          .getSystemKeyTypeToCounterNumberMap()
          .put(SystemKeyType.PERSONALIZATION, counterPersonalization);
    }
    if (counterKeyManagement != 0) {
      targetSamContextDto
          .getSystemKeyTypeToCounterNumberMap()
          .put(SystemKeyType.KEY_MANAGEMENT, counterKeyManagement);
    }
    if (counterReloading != 0) {
      targetSamContextDto
          .getSystemKeyTypeToCounterNumberMap()
          .put(SystemKeyType.RELOADING, counterReloading);
    }

    // compute needed counter file records
    Set<Integer> counterFileRecordNumbers = new HashSet<Integer>(3);
    if (counterPersonalization != 0) {
      counterFileRecordNumbers.add(counterToRecordLookup[counterPersonalization]);
    }
    if (counterKeyManagement != 0) {
      counterFileRecordNumbers.add(counterToRecordLookup[counterKeyManagement]);
    }
    if (counterReloading != 0) {
      counterFileRecordNumbers.add(counterToRecordLookup[counterReloading]);
    }

    // read counters
    for (Integer counterFileRecordNumber : counterFileRecordNumbers) {
      commands.add(new CommandReadCounter(getContext(), counterFileRecordNumber));
    }
    processTargetSamCommands(commands);

    if (counterPersonalization != 0) {
      targetSamContextDto
          .getCounterNumberToCounterValueMap()
          .put(
              counterPersonalization,
              getContext().getTargetSam().getCounter(counterPersonalization));
    }

    if (counterKeyManagement != 0) {
      targetSamContextDto
          .getCounterNumberToCounterValueMap()
          .put(counterKeyManagement, getContext().getTargetSam().getCounter(counterKeyManagement));
    }

    if (counterReloading != 0) {
      targetSamContextDto
          .getCounterNumberToCounterValueMap()
          .put(counterReloading, getContext().getTargetSam().getCounter(counterReloading));
    }

    // export as json
    return JsonUtil.toJson(targetSamContextDto);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public LSFreeTransactionManager processCommands() {
    processTargetSamCommands(false);
    return this;
  }

  /**
   * Prepares a "SelectDiversifier" command using a specific or the default key diversifier if it is
   * not already selected.
   *
   * @param specificKeyDiversifier The specific key diversifier (optional).
   * @since 0.1.0
   */
  private void prepareSelectDiversifierIfNeeded(byte[] specificKeyDiversifier) {
    if (specificKeyDiversifier != null) {
      if (!Arrays.equals(specificKeyDiversifier, currentKeyDiversifier)) {
        currentKeyDiversifier = specificKeyDiversifier;
        prepareSelectDiversifier();
      }
    } else {
      prepareSelectDiversifierIfNeeded();
    }
  }

  /**
   * Prepares a "SelectDiversifier" command using the default key diversifier if it is not already
   * selected.
   *
   * @since 0.1.0
   */
  private void prepareSelectDiversifierIfNeeded() {
    if (!Arrays.equals(currentKeyDiversifier, samKeyDiversifier)) {
      currentKeyDiversifier = samKeyDiversifier;
      prepareSelectDiversifier();
    }
  }

  /** Prepares a "SelectDiversifier" command using the current key diversifier. */
  private void prepareSelectDiversifier() {
    addTargetSamCommand(new CommandSelectDiversifier(getContext(), currentKeyDiversifier));
  }

  /**
   * Overlapping interval test
   *
   * @param startA beginning of the A interval.
   * @param endA end of the A interval.
   * @param startB beginning of the B interval.
   * @param endB end of the B interval.
   * @return true if the intervals A and B overlap.
   */
  private boolean areIntervalsOverlapping(int startA, int endA, int startB, int endB) {
    return startA <= endB && endA >= startB;
  }
}
