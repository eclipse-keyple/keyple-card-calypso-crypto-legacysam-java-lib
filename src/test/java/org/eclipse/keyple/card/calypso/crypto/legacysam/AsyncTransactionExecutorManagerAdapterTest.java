/* **************************************************************************************
 * Copyright (c) 2026 Calypso Networks Association https://calypsonet.org/
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

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.eclipse.keypop.card.CardSelectionResponseApi;
import org.eclipse.keypop.card.ProxyReaderApi;
import org.junit.Before;
import org.junit.Test;

public final class AsyncTransactionExecutorManagerAdapterTest {

  private static final String SAM_C1_POWER_ON_DATA = "3B3F9600805A4880C120501711223344829000";

  // Flags are held outside the test type so that reading them does not load this type
  private static boolean unexpectedTypeLoaded;
  private static boolean unexpectedTypeCreated;

  private ProxyReaderApi samReader;
  private LegacySamAdapter sam;

  @Before
  public void setUp() {
    samReader = mock(ProxyReaderApi.class);
    CardSelectionResponseApi samCardSelectionResponse = mock(CardSelectionResponseApi.class);
    when(samCardSelectionResponse.getPowerOnData()).thenReturn(SAM_C1_POWER_ON_DATA);
    sam = new LegacySamAdapter(samCardSelectionResponse);
  }

  @Test
  public void constructor_whenCommandTypeIsUnknown_shouldThrowISE() {
    String samCommands = buildSamCommandsJson("com.unknown.DoesNotExist");
    assertThatThrownBy(
            () -> new AsyncTransactionExecutorManagerAdapter(samReader, sam, samCommands))
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  public void constructor_whenCommandTypeIsNotACommand_shouldThrowIAE() {
    String samCommands = buildSamCommandsJson(UnexpectedType.class.getName());
    assertThatThrownBy(
            () -> new AsyncTransactionExecutorManagerAdapter(samReader, sam, samCommands))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("is not a SAM command");
    assertThat(unexpectedTypeLoaded).isFalse();
    assertThat(unexpectedTypeCreated).isFalse();
  }

  @Test
  public void constructor_whenCommandTypeIsASamCommand_shouldNotThrow() {
    String samCommands = buildSamCommandsJson(CommandWriteCeilings.class.getName());
    assertThatCode(() -> new AsyncTransactionExecutorManagerAdapter(samReader, sam, samCommands))
        .doesNotThrowAnyException();
  }

  private static String buildSamCommandsJson(String commandType) {
    return "{\"samCommandsTypes\":[\""
        + commandType
        + "\"],\"samCommands\":[{\"payload\":\"value\"}]}";
  }

  public static class UnexpectedType {
    static {
      unexpectedTypeLoaded = true;
    }

    public String payload;

    public UnexpectedType() {
      unexpectedTypeCreated = true;
    }
  }
}
