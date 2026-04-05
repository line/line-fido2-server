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

package com.linecorp.line.auth.fido.fido2.server.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.linecorp.line.auth.fido.fido2.common.COSEAlgorithmIdentifier;
import com.linecorp.line.auth.fido.fido2.common.PublicKeyCredentialParameters;
import com.linecorp.line.auth.fido.fido2.common.PublicKeyCredentialType;
import com.linecorp.line.auth.fido.fido2.common.crypto.Digests;
import com.linecorp.line.auth.fido.fido2.common.server.COSEAlgorithm;
import com.linecorp.line.auth.fido.fido2.server.attestation.AttestationVerifierFactory;
import com.linecorp.line.auth.fido.fido2.server.attestation.android.keyattestation.RevokeCheckerClient;
import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;
import com.linecorp.line.auth.fido.fido2.server.exception.FIDO2ServerRuntimeException;
import com.linecorp.line.auth.fido.fido2.server.model.AttestationObject;
import com.linecorp.line.auth.fido.fido2.server.model.AttestedCredentialData;
import com.linecorp.line.auth.fido.fido2.server.model.AuthenticatorData;
import com.linecorp.line.auth.fido.fido2.server.model.ECCKey;
import com.linecorp.line.auth.fido.fido2.server.model.RSAKey;
import com.linecorp.line.auth.fido.fido2.server.property.Fido2Properties;
import com.linecorp.line.auth.fido.fido2.server.property.Fido2Properties.RegistrationProperties;

class AttestationServiceImplTest {
    private final MetadataService metadataService = mock();
    private final VendorSpecificMetadataService vendorSpecificMetadataService = mock();
    private final AttestationVerifierFactory attestationVerifierFactory = mock();
    private final RevokeCheckerClient revokeCheckerClient = mock();
    private final Fido2Properties fido2Properties = new Fido2Properties(
            3000,
            true,
            true,
            new RegistrationProperties(
                    List.of("ES256")
            )
    );

    private final AttestationServiceImpl cut = new AttestationServiceImpl(
            metadataService,
            vendorSpecificMetadataService,
            attestationVerifierFactory,
            revokeCheckerClient,
            fido2Properties
    );

    private static final String RP_ID = "example.com";

    private static AttestationObject createAttestationObject(COSEAlgorithm algorithm) {
        final ECCKey eccKey = ECCKey.builder()
                                    .algorithm(algorithm)
                                    .build();

        final AttestedCredentialData attestedCredentialData = new AttestedCredentialData();
        attestedCredentialData.setAaguid(new byte[16]);
        attestedCredentialData.setCredentialId(new byte[32]);
        attestedCredentialData.setCredentialPublicKey(eccKey);

        final AuthenticatorData authData = AuthenticatorData.builder()
                                                            .rpIdHash(Digests.sha256(RP_ID.getBytes(StandardCharsets.UTF_8)))
                                                            .userPresent(true)
                                                            .userVerified(false)
                                                            .atIncluded(true)
                                                            .edIncluded(false)
                                                            .signCount(0)
                                                            .attestedCredentialData(attestedCredentialData)
                                                            .build();

        final AttestationObject attestationObject = new AttestationObject();
        attestationObject.setAuthData(authData);
        return attestationObject;
    }

    private static PublicKeyCredentialParameters createPubKeyCredParam(COSEAlgorithmIdentifier alg) {
        final PublicKeyCredentialParameters param = new PublicKeyCredentialParameters();
        param.setType(PublicKeyCredentialType.PUBLIC_KEY);
        param.setAlg(alg);
        return param;
    }

    @Test
    void attestationObjectValidationCheck_allowedAlgorithm_passes() {
        final AttestationObject attestationObject = createAttestationObject(COSEAlgorithm.ES256);
        final List<PublicKeyCredentialParameters> params = Arrays.asList(
                createPubKeyCredParam(COSEAlgorithmIdentifier.ES256),
                createPubKeyCredParam(COSEAlgorithmIdentifier.RS256)
        );

        assertDoesNotThrow(() ->
                cut.attestationObjectValidationCheck(RP_ID, null, attestationObject, null, params));
    }

    @Test
    void attestationObjectValidationCheck_notAllowedAlgorithm_throws() {
        final AttestationObject attestationObject = createAttestationObject(COSEAlgorithm.ES256);
        final List<PublicKeyCredentialParameters> params = Collections.singletonList(
                createPubKeyCredParam(COSEAlgorithmIdentifier.RS256)
        );

        final FIDO2ServerRuntimeException ex = assertThrows(FIDO2ServerRuntimeException.class, () ->
                cut.attestationObjectValidationCheck(RP_ID, null, attestationObject, null, params));
        assertEquals(InternalErrorCode.NOT_ALLOWED_COSE_ALGORITHM, ex.getErrorCode());
    }

    @Test
    void attestationObjectValidationCheck_emptyParamList_throws() {
        final AttestationObject attestationObject = createAttestationObject(COSEAlgorithm.ES256);
        final List<PublicKeyCredentialParameters> params = Collections.emptyList();

        final FIDO2ServerRuntimeException ex = assertThrows(FIDO2ServerRuntimeException.class, () ->
                cut.attestationObjectValidationCheck(RP_ID, null, attestationObject, null, params));
        assertEquals(InternalErrorCode.NOT_ALLOWED_COSE_ALGORITHM, ex.getErrorCode());
    }

    @Test
    void attestationObjectValidationCheck_rsaKeyAllowed_passes() {
        final RSAKey rsaKey = RSAKey.builder()
                                    .algorithm(COSEAlgorithm.RS256)
                                    .build();

        final AttestedCredentialData attestedCredentialData = new AttestedCredentialData();
        attestedCredentialData.setAaguid(new byte[16]);
        attestedCredentialData.setCredentialId(new byte[32]);
        attestedCredentialData.setCredentialPublicKey(rsaKey);

        final AuthenticatorData authData = AuthenticatorData.builder()
                                                            .rpIdHash(Digests.sha256(RP_ID.getBytes(StandardCharsets.UTF_8)))
                                                            .userPresent(true)
                                                            .userVerified(false)
                                                            .atIncluded(true)
                                                            .edIncluded(false)
                                                            .signCount(0)
                                                            .attestedCredentialData(attestedCredentialData)
                                                            .build();

        final AttestationObject attestationObject = new AttestationObject();
        attestationObject.setAuthData(authData);

        final List<PublicKeyCredentialParameters> params = Collections.singletonList(
                createPubKeyCredParam(COSEAlgorithmIdentifier.RS256)
        );

        assertDoesNotThrow(() ->
                cut.attestationObjectValidationCheck(RP_ID, null, attestationObject, null, params));
    }

    @Test
    void attestationObjectValidationCheck_rsaKeyNotAllowed_throws() {
        final RSAKey rsaKey = RSAKey.builder()
                                    .algorithm(COSEAlgorithm.RS256)
                                    .build();

        final AttestedCredentialData attestedCredentialData = new AttestedCredentialData();
        attestedCredentialData.setAaguid(new byte[16]);
        attestedCredentialData.setCredentialId(new byte[32]);
        attestedCredentialData.setCredentialPublicKey(rsaKey);

        final AuthenticatorData authData = AuthenticatorData.builder()
                                                            .rpIdHash(Digests.sha256(RP_ID.getBytes(StandardCharsets.UTF_8)))
                                                            .userPresent(true)
                                                            .userVerified(false)
                                                            .atIncluded(true)
                                                            .edIncluded(false)
                                                            .signCount(0)
                                                            .attestedCredentialData(attestedCredentialData)
                                                            .build();

        final AttestationObject attestationObject = new AttestationObject();
        attestationObject.setAuthData(authData);

        final List<PublicKeyCredentialParameters> params = Collections.singletonList(
                createPubKeyCredParam(COSEAlgorithmIdentifier.ES256)
        );

        final FIDO2ServerRuntimeException ex = assertThrows(FIDO2ServerRuntimeException.class, () ->
                cut.attestationObjectValidationCheck(RP_ID, null, attestationObject, null, params));
        assertEquals(InternalErrorCode.NOT_ALLOWED_COSE_ALGORITHM, ex.getErrorCode());
    }
}
