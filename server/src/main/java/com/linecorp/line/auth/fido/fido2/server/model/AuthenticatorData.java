/*
 * Copyright 2021 LINE Corporation
 *
 * LINE Corporation licenses this file to you under the Apache License,
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

import java.io.ByteArrayInputStream;
import java.io.IOException;

import com.linecorp.line.auth.fido.fido2.server.util.UnsignedUtil;

import lombok.Data;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;

@Data
@Slf4j
@SuperBuilder
public class AuthenticatorData {

    static final int UP_MASK = 1;
    static final int UV_MASK = 1 << 2;
    static final int AT_MASK = 1 << 6;
    static final int ED_MASK = 1 << 7;

    private byte[] rpIdHash;
    private boolean userPresent;
    private boolean userVerified;
    private boolean atIncluded;
    private boolean edIncluded;
    private long signCount;
    private AttestedCredentialData attestedCredentialData;
    private AuthenticatorExtension extensions;
    private byte[] bytes;

    public static AuthenticatorData decode(byte[] encoded) throws IOException {

        ByteArrayInputStream inputStream = new ByteArrayInputStream(encoded);

        // rpIdHash
        byte[] rpIdHash = new byte[32];
        inputStream.read(rpIdHash, 0, rpIdHash.length);

        // flags
        int flags = inputStream.read();
        AuthenticatorData authenticatorData = decodeAuthenticatorDataCommon(encoded, inputStream, rpIdHash, flags);

        AuthenticatorExtension extensions = null;
        boolean edIncluded = (flags & ED_MASK) == ED_MASK;
        if (edIncluded) {
            extensions = decodeAuthenticatorDataExtension(inputStream);
        }
        authenticatorData.setExtensions(extensions);
        authenticatorData.setEdIncluded(edIncluded);

        if (inputStream.available() > 0) {
            // remaining byte array
            throw new IOException("Attestation data contains left over bytes " + inputStream.available());
        }

        return authenticatorData;
    }

    protected static AuthenticatorData decodeAuthenticatorDataCommon(byte[] encoded, ByteArrayInputStream inputStream, byte[] rpIdHash, int flags) throws IOException {

        boolean userPresent = (flags & UP_MASK) == UP_MASK;
        boolean userVerified = (flags & UV_MASK) == UV_MASK;
        boolean atIncluded = (flags & AT_MASK) == AT_MASK;

        AttestedCredentialData attestedCredentialData = null;

        // signCounter
        byte[] signCounterBytes = new byte[4];
        inputStream.read(signCounterBytes, 0, signCounterBytes.length);
        long signCounter = UnsignedUtil.readUINT32BE(signCounterBytes);

        // attested cred. data
        if (atIncluded) {
            // aaguid
            byte[] aaguidBytes = new byte[16];
            inputStream.read(aaguidBytes, 0, aaguidBytes.length);

            // credentialIdLength
            byte[] credentialIdLengthBytes = new byte[2];
            inputStream.read(credentialIdLengthBytes, 0, credentialIdLengthBytes.length);
            int credentialIdLength = UnsignedUtil.readUINT16BE(credentialIdLengthBytes);

            // credentialId
            byte[] credentialIdBytes = new byte[credentialIdLength];
            inputStream.read(credentialIdBytes, 0, credentialIdLength);

            // cbor decoding
            CredentialPublicKey credentialPublicKey = CredentialPublicKey.decode(inputStream);

            attestedCredentialData = new AttestedCredentialData();
            attestedCredentialData.setAaguid(aaguidBytes);
            attestedCredentialData.setCredentialId(credentialIdBytes);
            attestedCredentialData.setCredentialPublicKey(credentialPublicKey);
        }

        return AuthenticatorData.builder()
                .rpIdHash(rpIdHash)
                .signCount(signCounter)
                .userPresent(userPresent)
                .userVerified(userVerified)
                .atIncluded(atIncluded)
                .bytes(encoded)
                .attestedCredentialData(attestedCredentialData)
                .build();
    }

    protected static AuthenticatorExtension decodeAuthenticatorDataExtension(ByteArrayInputStream inputStream) throws IOException {
        log.info("Extension is included");
        int extensionDataLength = inputStream.available();
        if (extensionDataLength > 0) {
            byte[] extensionsBytes = new byte[extensionDataLength];
            inputStream.read(extensionsBytes);
            return AuthenticatorExtension.decode(extensionsBytes);
        } else {
            throw new IOException("No available bytes in Authenticator data for extensions");
        }
    }
}
