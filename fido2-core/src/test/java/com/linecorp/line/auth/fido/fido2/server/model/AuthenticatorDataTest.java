/*
 * Copyright 2026 LY Corporation
 *
 * LY Corporation licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.linecorp.line.auth.fido.fido2.server.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;

import org.junit.jupiter.api.Test;

import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;
import com.linecorp.line.auth.fido.fido2.server.exception.FIDO2ServerRuntimeException;

class AuthenticatorDataTest {
    /**
     * Builds minimal authenticator data bytes: 32-byte rpIdHash + 1-byte flags + 4-byte signCount.
     */
    private static byte[] buildAuthenticatorData(int flags, long signCount) {
        final ByteBuffer buffer = ByteBuffer.allocate(37);
        buffer.put(new byte[32]); // rpIdHash
        buffer.put((byte) flags);
        buffer.putInt((int) signCount);
        return buffer.array();
    }

    @Test
    void decode_backupEligibleAndBackupState_bothTrue() throws IOException {
        // BE=1, BS=1
        final int flags = AuthenticatorData.BE_MASK | AuthenticatorData.BS_MASK;
        final byte[] encoded = buildAuthenticatorData(flags, 0);

        final AuthenticatorData result = AuthenticatorData.decode(encoded);

        assertTrue(result.isBackupEligibility());
        assertTrue(result.isBackupState());
    }

    @Test
    void decode_backupEligibleOnly_backupStateFalse() throws IOException {
        // BE=1, BS=0
        final int flags = AuthenticatorData.BE_MASK;
        final byte[] encoded = buildAuthenticatorData(flags, 0);

        final AuthenticatorData result = AuthenticatorData.decode(encoded);

        assertTrue(result.isBackupEligibility());
        assertFalse(result.isBackupState());
    }

    @Test
    void decode_neitherBackupEligibleNorBackupState() throws IOException {
        // BE=0, BS=0
        final byte[] encoded = buildAuthenticatorData(0, 0);

        final AuthenticatorData result = AuthenticatorData.decode(encoded);

        assertFalse(result.isBackupEligibility());
        assertFalse(result.isBackupState());
    }

    @Test
    void decode_backupStateWithoutBackupEligibility_throwsException() {
        // BE=0, BS=1 — invalid state
        final int flags = AuthenticatorData.BS_MASK;
        final byte[] encoded = buildAuthenticatorData(flags, 0);

        final FIDO2ServerRuntimeException exception = assertThrows(
                FIDO2ServerRuntimeException.class,
                () -> AuthenticatorData.decode(encoded)
        );

        assertEquals(InternalErrorCode.INVALID_BACKUP_STATE_FLAG_SET, exception.getErrorCode());
    }

    @Test
    void decode_allFlagsCombined_parsedCorrectly() throws IOException {
        // UP=1, UV=1, BE=1, BS=1
        final int flags = AuthenticatorData.UP_MASK | AuthenticatorData.UV_MASK
                          | AuthenticatorData.BE_MASK | AuthenticatorData.BS_MASK;
        final byte[] encoded = buildAuthenticatorData(flags, 42);

        final AuthenticatorData result = AuthenticatorData.decode(encoded);

        assertTrue(result.isUserPresent());
        assertTrue(result.isUserVerified());
        assertTrue(result.isBackupEligibility());
        assertTrue(result.isBackupState());
        assertFalse(result.isAtIncluded());
        assertEquals(42, result.getSignCount());
    }
}
