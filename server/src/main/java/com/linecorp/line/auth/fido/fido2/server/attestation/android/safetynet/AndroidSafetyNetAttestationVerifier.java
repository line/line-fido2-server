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

package com.linecorp.line.auth.fido.fido2.server.attestation.android.safetynet;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.linecorp.line.auth.fido.fido2.common.crypto.Digests;
import com.linecorp.line.auth.fido.fido2.common.server.AttestationType;
import com.linecorp.line.auth.fido.fido2.server.attestation.AttestationVerificationResult;
import com.linecorp.line.auth.fido.fido2.server.attestation.AttestationVerifier;
import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;
import com.linecorp.line.auth.fido.fido2.server.exception.FIDO2ServerRuntimeException;
import com.linecorp.line.auth.fido.fido2.server.model.AttestationStatement;
import com.linecorp.line.auth.fido.fido2.server.model.AttestationStatementFormatIdentifier;
import com.linecorp.line.auth.fido.fido2.server.model.AuthenticatorData;
import com.linecorp.line.auth.fido.fido2.server.util.CertificateUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

@Slf4j
@Component
public class AndroidSafetyNetAttestationVerifier implements AttestationVerifier {
    private static final String ALGORITHM_RS256 = "RS256";
    private static final String ALGORITHM_RS384 = "RS384";
    private static final String ALGORITHM_RS512 = "RS512";
    private static final String ALGORITHM_ES256 = "ES256";
    private static final String ALGORITHM_ES384 = "ES384";
    private static final String ALGORITHM_ES512 = "ES512";
    private static final String ISSUER_HOST_NAME = "attest.android.com";


    @Override
    public AttestationStatementFormatIdentifier getIdentifier() {
        return AttestationStatementFormatIdentifier.ANDROID_SAFETYNET;
    }

    @Override
    public AttestationVerificationResult verify(AttestationStatement attestationStatement, AuthenticatorData authenticatorData,
                                                byte[] clientDataHash) {
        AndroidSafetyNetAttestationStatement androidSafetyNet = (AndroidSafetyNetAttestationStatement) attestationStatement;
        boolean result = false;

        // check version
        String safetyNetVersion = androidSafetyNet.getVer();
        if (StringUtils.isEmpty(safetyNetVersion)) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_ATTESTATION_FORMAT, "Version is missing");
        }
        if (androidSafetyNet.getResponse() == null || androidSafetyNet.getResponse().length == 0) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_ATTESTATION_FORMAT, "Response is missing");
        }

        byte[] response = androidSafetyNet.getResponse();
        String attestationResponseString = new String(response);

        DecodedJWT decodedJWT = JWT.decode(attestationResponseString);

        List<String> certificateList = decodedJWT.getHeaderClaim("x5c").asList(String.class);

        List<Certificate> attestationCertificates;
        try {
            attestationCertificates = CertificateUtil.getCertificatesFromStringList(certificateList);
        } catch (CertificateException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.ANDROID_SAFETYNET_ATTESTATION_CERTIFICATE_INVALID, e);
        }

        if (attestationCertificates == null ||
            attestationCertificates.isEmpty()) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.ANDROID_SAFETYNET_ATTESTATION_CERTIFICATE_NOT_INCLUDED);
        }

        Certificate attestationCertificate = attestationCertificates.get(0);
        PublicKey publicKey = attestationCertificate.getPublicKey();

        // get jwt signature algorithm
        String algorithm = decodedJWT.getAlgorithm();
        Algorithm signatureAlgorithm;
        if (ALGORITHM_RS256.equals(algorithm)) {
            signatureAlgorithm = Algorithm.RSA256((RSAPublicKey) publicKey, null);
        } else if (ALGORITHM_RS384.equals(algorithm)) {
            signatureAlgorithm = Algorithm.RSA384((RSAPublicKey) publicKey, null);
        } else if (ALGORITHM_RS512.equals(algorithm)) {
            signatureAlgorithm = Algorithm.RSA512((RSAPublicKey) publicKey, null);
        } else if (ALGORITHM_ES256.equals(algorithm)) {
            signatureAlgorithm = Algorithm.ECDSA256((ECPublicKey) publicKey, null);
        } else if (ALGORITHM_ES384.equals(algorithm)) {
            signatureAlgorithm = Algorithm.ECDSA384((ECPublicKey) publicKey, null);
        } else if (ALGORITHM_ES512.equals(algorithm)) {
            signatureAlgorithm = Algorithm.ECDSA512((ECPublicKey) publicKey, null);
        } else {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.ANDROID_SAFETYNET_ATTESTATION_NOT_SUPPORTED_SIGNATURE_ALGORITHM,
                                                  "Algorithm name: " + algorithm);
        }

        // verify jwt signature
        JWTVerifier jwtVerifier = JWT.require(signatureAlgorithm).build();
        try {
            decodedJWT = jwtVerifier.verify(attestationResponseString);
            String payload = decodedJWT.getPayload();
            String decodedPayload = new String(Base64.getUrlDecoder().decode(payload));
            // json parse
            ObjectMapper objectMapper = new ObjectMapper();
            try {
                AttestationStatementInfo attestationStatementInfo =
                        objectMapper.readValue(decodedPayload, AttestationStatementInfo.class);

                // check nonce
                // TODO: Need to check spec
                byte[] concatBytes = ByteBuffer
                        .allocate(authenticatorData.getBytes().length + clientDataHash.length)
                        .put(authenticatorData.getBytes())
                        .put(clientDataHash)
                        .array();

                byte[] digestBytes = Digests.sha256(concatBytes);
                byte[] nonceBytes = Base64.getDecoder().decode(attestationStatementInfo.getNonce());

                if (!Arrays.equals(digestBytes, nonceBytes)) {
                    throw new FIDO2ServerRuntimeException(InternalErrorCode.ANDROID_SAFETYNET_ATTESTATION_NONCE_NOT_MATCHED);
                }

                // check attestation issuer host name
                String dn = ((X509Certificate) attestationCertificate).getSubjectDN().getName();
                int index = dn.indexOf("CN");
                StringBuffer buffer = new StringBuffer();
                if (index >= 0) {
                    for (int i = index + 3; i < dn.length(); i++) {
                        if (dn.charAt(i) == ',') {
                            break;
                        }
                        buffer.append(dn.charAt(i));
                    }
                }

                if (buffer.length() == 0 ||
                    (buffer.length() > 0 &&
                    !ISSUER_HOST_NAME.equals(buffer.toString()))) {
                    throw new FIDO2ServerRuntimeException(InternalErrorCode.ANDROID_SAFETYNET_ATTESTATION_CERTIFICATE_ISSUER_NAME_INVALID);
                }

                // check ctsProfileMatch, should be true
                if(!attestationStatementInfo.isCtsProfileMatch()) {
                    throw new FIDO2ServerRuntimeException(InternalErrorCode.ANDROID_SAFETYNET_ATTESTATION_CTS_PROFILE_MATCH_NOT_SET);
                }

                // check timestamp
                long currentTime = System.currentTimeMillis();
                if (attestationStatementInfo.getTimestampMs() >= currentTime) {
                    throw new FIDO2ServerRuntimeException(InternalErrorCode.ANDROID_SAFETYNET_ATTESTATION_TIMESTAMP_INVALID);
                }
                if ((currentTime - attestationStatementInfo.getTimestampMs()) > 60 * 100) {
                    throw new FIDO2ServerRuntimeException(InternalErrorCode.ANDROID_SAFETYNET_ATTESTATION_TIMESTAMP_INVALID);
                }

            } catch (IOException e) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.ANDROID_SAFETYNET_ATTESTATION_DATA_INVALID, e);
            }

            result = true;

        } catch (JWTVerificationException e) {
            // do nothing
        }

        return AttestationVerificationResult
                .builder()
                .success(result)
                .type(AttestationType.BASIC)
                .trustPath(attestationCertificates)
                .format(AttestationStatementFormatIdentifier.ANDROID_SAFETYNET)
                .build();

    }
}
