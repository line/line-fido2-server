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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;

import org.junit.jupiter.api.Test;

import com.linecorp.line.auth.fido.fido2.common.server.COSEAlgorithm;
import com.linecorp.line.auth.fido.fido2.server.cose.COSEEllipticCurve;
import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;
import com.linecorp.line.auth.fido.fido2.server.exception.FIDO2ServerRuntimeException;

class AuthenticatorDataTest {
    /**
     * Builds authenticator data bytes with configurable sections.
     *
     * <p>Always writes: 32-byte zero-filled rpIdHash + 1-byte flags + 4-byte signCount.
     *
     * <p>When AT_MASK is set in {@code flags}, the attested credential data section is appended:
     * 16-byte zero-filled aaguid + 2-byte unsigned big-endian credentialIdLength +
     * {@code credentialIdLength} zero bytes of credentialId + a CBOR-encoded ES256/P-256
     * public key (zero-filled x/y).
     *
     * <p>AT_MASK and {@code credentialIdLength} must agree: either both are present, or neither
     * is. Mismatched input raises {@link IllegalArgumentException}.
     */
    private static byte[] buildAuthenticatorData(
            int flags, long signCount, Integer credentialIdLength) {
        final boolean atIncluded = (flags & AuthenticatorData.AT_MASK) != 0;
        if (atIncluded != (credentialIdLength != null)) {
            throw new IllegalArgumentException(
                    "AT_MASK in flags must correspond to a non-null credentialIdLength");
        }

        int size = 32 + 1 + 4;
        byte[] publicKeyBytes = null;
        if (atIncluded) {
            try {
                publicKeyBytes = ECCKey.builder()
                        .algorithm(COSEAlgorithm.ES256)
                        .curve(COSEEllipticCurve.P256)
                        .x(new byte[32])
                        .y(new byte[32])
                        .build()
                        .encode();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            size += 16 + 2 + credentialIdLength + publicKeyBytes.length;
        }

        final ByteBuffer buffer = ByteBuffer.allocate(size);
        buffer.put(new byte[32]); // rpIdHash
        buffer.put((byte) flags);
        buffer.putInt((int) signCount);
        if (atIncluded) {
            buffer.put(new byte[16]); // aaguid
            buffer.putShort(credentialIdLength.shortValue());
            buffer.put(new byte[credentialIdLength]); // credentialId
            buffer.put(publicKeyBytes);
        }
        return buffer.array();
    }

    @Test
    void decode_backupEligibleAndBackupState_bothTrue() throws IOException {
        // BE=1, BS=1
        final int flags = AuthenticatorData.BE_MASK | AuthenticatorData.BS_MASK;
        final byte[] encoded = buildAuthenticatorData(flags, 0, null);

        final AuthenticatorData result = AuthenticatorData.decode(encoded);

        assertTrue(result.isBackupEligibility());
        assertTrue(result.isBackupState());
    }

    @Test
    void decode_backupEligibleOnly_backupStateFalse() throws IOException {
        // BE=1, BS=0
        final int flags = AuthenticatorData.BE_MASK;
        final byte[] encoded = buildAuthenticatorData(flags, 0, null);

        final AuthenticatorData result = AuthenticatorData.decode(encoded);

        assertTrue(result.isBackupEligibility());
        assertFalse(result.isBackupState());
    }

    @Test
    void decode_neitherBackupEligibleNorBackupState() throws IOException {
        // BE=0, BS=0
        final byte[] encoded = buildAuthenticatorData(0, 0, null);

        final AuthenticatorData result = AuthenticatorData.decode(encoded);

        assertFalse(result.isBackupEligibility());
        assertFalse(result.isBackupState());
    }

    @Test
    void decode_backupStateWithoutBackupEligibility_throwsException() {
        // BE=0, BS=1 — invalid state
        final int flags = AuthenticatorData.BS_MASK;
        final byte[] encoded = buildAuthenticatorData(flags, 0, null);

        final FIDO2ServerRuntimeException exception = assertThrows(
                FIDO2ServerRuntimeException.class,
                () -> AuthenticatorData.decode(encoded)
        );

        assertEquals(InternalErrorCode.INVALID_BACKUP_STATE_FLAG_SET, exception.getErrorCode());
    }

    @Test
    void decode_zeroCredentialIdLength_throwsException() {
        final byte[] encoded = buildAuthenticatorData(AuthenticatorData.AT_MASK, 0, 0);

        final FIDO2ServerRuntimeException exception = assertThrows(
                FIDO2ServerRuntimeException.class,
                () -> AuthenticatorData.decode(encoded)
        );

        assertEquals(InternalErrorCode.INVALID_CREDENTIAL_ID_LENGTH, exception.getErrorCode());
    }

    @Test
    void decode_256CredentialIdLength_success() {
        final byte[] encoded = buildAuthenticatorData(AuthenticatorData.AT_MASK, 0, 256);

        assertDoesNotThrow(() -> AuthenticatorData.decode(encoded));
    }

    @Test
    void decode_credentialIdLengthExceedingMax_throwsException() {
        // 1024 is the first value over the 1023-byte upper bound
        final byte[] encoded = buildAuthenticatorData(AuthenticatorData.AT_MASK, 0, 1024);

        final FIDO2ServerRuntimeException exception = assertThrows(
                FIDO2ServerRuntimeException.class,
                () -> AuthenticatorData.decode(encoded)
        );

        assertEquals(InternalErrorCode.INVALID_CREDENTIAL_ID_LENGTH, exception.getErrorCode());
    }

    @Test
    void decode_maxUnsignedCredentialIdLength_throwsException() {
        // 0xFFFF — largest value representable in the uint16 length field
        final byte[] encoded = buildAuthenticatorData(AuthenticatorData.AT_MASK, 0, 0xFFFF);

        final FIDO2ServerRuntimeException exception = assertThrows(
                FIDO2ServerRuntimeException.class,
                () -> AuthenticatorData.decode(encoded)
        );

        assertEquals(InternalErrorCode.INVALID_CREDENTIAL_ID_LENGTH, exception.getErrorCode());
    }

    @Test
    void decode_allFlagsCombined_parsedCorrectly() throws IOException {
        // UP=1, UV=1, BE=1, BS=1
        final int flags = AuthenticatorData.UP_MASK | AuthenticatorData.UV_MASK
                          | AuthenticatorData.BE_MASK | AuthenticatorData.BS_MASK;
        final byte[] encoded = buildAuthenticatorData(flags, 42, null);

        final AuthenticatorData result = AuthenticatorData.decode(encoded);

        assertTrue(result.isUserPresent());
        assertTrue(result.isUserVerified());
        assertTrue(result.isBackupEligibility());
        assertTrue(result.isBackupState());
        assertFalse(result.isAtIncluded());
        assertEquals(42, result.getSignCount());
    }
}
