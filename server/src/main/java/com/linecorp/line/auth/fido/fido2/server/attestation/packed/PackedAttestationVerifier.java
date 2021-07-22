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

package com.linecorp.line.auth.fido.fido2.server.attestation.packed;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.springframework.stereotype.Component;

import com.linecorp.line.auth.fido.fido2.server.model.OctetKey;
import com.linecorp.line.auth.fido.fido2.server.util.CertificateUtil;
import com.linecorp.line.auth.fido.fido2.server.util.PublicKeyUtil;
import com.linecorp.line.auth.fido.fido2.server.attestation.AttestationVerificationResult;
import com.linecorp.line.auth.fido.fido2.server.attestation.AttestationVerifier;
import com.linecorp.line.auth.fido.fido2.common.server.COSEAlgorithm;
import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;
import com.linecorp.line.auth.fido.fido2.server.exception.FIDO2ServerRuntimeException;
import com.linecorp.line.auth.fido.fido2.server.helper.SignatureHelper;
import com.linecorp.line.auth.fido.fido2.server.model.AttestationStatement;
import com.linecorp.line.auth.fido.fido2.server.model.AttestationStatementFormatIdentifier;
import com.linecorp.line.auth.fido.fido2.common.server.AttestationType;
import com.linecorp.line.auth.fido.fido2.server.model.AuthenticatorData;
import com.linecorp.line.auth.fido.fido2.server.model.CredentialPublicKey;
import com.linecorp.line.auth.fido.fido2.server.model.ECCKey;
import com.linecorp.line.auth.fido.fido2.server.model.RSAKey;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class PackedAttestationVerifier implements AttestationVerifier {

    private static final String OID_FIDO_GEN_CE_AAGUID = "1.3.6.1.4.1.45724.1.1.4";

    @Override
    public AttestationStatementFormatIdentifier getIdentifier() {
        return AttestationStatementFormatIdentifier.PACKED;
    }

    @Override
    public AttestationVerificationResult verify(AttestationStatement attestationStatement, AuthenticatorData authenticatorData,
                                                byte[] clientDataHash) {
        PackedAttestationStatement packed = (PackedAttestationStatement) attestationStatement;

        // check validity
        if (packed.getSig() == null ||
                packed.getSig().length == 0) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_ATTESTATION_FORMAT);
        }

        if (packed.getEcdaaKeyId() != null &&
                packed.getEcdaaKeyId().length > 0) { // ecdaa
            throw new FIDO2ServerRuntimeException(InternalErrorCode.ECDAA_ALGORITHM_NOT_SUPPORTED);
        }

        COSEAlgorithm algorithm;
        try {
            algorithm = COSEAlgorithm.fromValue(packed.getAlg());
        } catch (NoSuchElementException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_COSE_ALGORITHM, "Alg " + packed.getAlg());
        }

        log.info("Prepare toBeSignedMessage");
        byte[] toBeSignedMessage = ByteBuffer
                .allocate(authenticatorData.getBytes().length + clientDataHash.length)
                .put(authenticatorData.getBytes())
                .put(clientDataHash)
                .array();
        log.debug("toBeSignedMessage (b64url enc): {}", Base64.getUrlEncoder().withoutPadding().encodeToString(toBeSignedMessage));

        // attestation type
        // basic
        if (packed.getX5c() != null &&
            !packed.getX5c().isEmpty()) {
            log.info("Basic Attestation Type");
            log.info("Generate certificate list with x5c");
            List<Certificate> certificateList;
            try {
                certificateList = CertificateUtil.getCertificates(packed.getX5c());
            } catch (CertificateException e) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.ATTESTATION_CERTIFICATE_ERROR, e);
            }

            PublicKey publicKey = certificateList.get(0).getPublicKey();

            // verify signature /w public key, toBeSignedMessage, signature, algorithm
            log.info("Verify signature /w public key in leaf cert {}, toBeSignedMessage {}, signature {}, algorithm {}",
                    Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getEncoded()),
                    Base64.getUrlEncoder().withoutPadding().encodeToString(toBeSignedMessage),
                    Base64.getUrlEncoder().withoutPadding().encodeToString(packed.getSig()), algorithm);
            boolean result = SignatureHelper.verifySignature(publicKey, toBeSignedMessage, packed.getSig(), algorithm);

            X509Certificate certificate = (X509Certificate) certificateList.get(0);
            byte[] aaguidFromCredCert = extractAaguidFromCredCert(certificate);
            if(aaguidFromCredCert != null) {
                byte[] aaguidFromAttestedCredentialData = authenticatorData.getAttestedCredentialData().getAaguid();
                if (!Arrays.equals(aaguidFromCredCert, aaguidFromAttestedCredentialData)) {
                    throw new FIDO2ServerRuntimeException(InternalErrorCode.PACKED_ATTESTATION_AAGUID_NOT_MATCHED);
                }
            }

            return AttestationVerificationResult
                    .builder()
                    .success(result)
                    .type(AttestationType.BASIC)
                    .trustPath(certificateList)
                    .format(AttestationStatementFormatIdentifier.PACKED)
                    .build();
        } else {    // self
            log.info("Self Attestation Type");
            CredentialPublicKey credentialPublicKey = authenticatorData.getAttestedCredentialData().getCredentialPublicKey();

            log.info("Get credential public key for verifying signature");
            PublicKey publicKey;
            if (algorithm.isRSAAlgorithm()) {
                if (credentialPublicKey instanceof RSAKey) {
                    RSAKey rsaKey = (RSAKey) credentialPublicKey;
                    if (algorithm != rsaKey.getAlgorithm()) {
                        // error (not matched)
                        throw new FIDO2ServerRuntimeException(InternalErrorCode.PACKED_ATTESTATION_ALGORITHM_NOT_MATCHED,
                                                              "Alg in statement: " + algorithm + ", in credential public key: " + rsaKey.getAlgorithm());
                    } else {
                        // convert
                        try {
                            publicKey = PublicKeyUtil.getRSAPublicKey(rsaKey.getN(), rsaKey.getE());
                        } catch (GeneralSecurityException e) {
                            throw new FIDO2ServerRuntimeException(InternalErrorCode.USER_PUBLIC_KEY_INVALID_KEY_SPEC, e);
                        }
                    }
                } else {
                    // error
                    throw new FIDO2ServerRuntimeException(InternalErrorCode.PACKED_ATTESTATION_ALGORITHM_NOT_MATCHED);
                }
            } else if (algorithm.isECCAlgorithm()) {
                if (credentialPublicKey instanceof ECCKey) {
                    ECCKey eccKey = (ECCKey) credentialPublicKey;
                    if (algorithm != eccKey.getAlgorithm()) {
                        // error (not matched)
                        throw new FIDO2ServerRuntimeException(InternalErrorCode.PACKED_ATTESTATION_ALGORITHM_NOT_MATCHED,
                                                              "Alg in statement: " + algorithm + ", in credential public key: " + eccKey.getAlgorithm());
                    } else {
                        // convert
                        try {
                            publicKey = PublicKeyUtil.getECDSAPublicKey(eccKey.getX(), eccKey.getY(),
                                                                        eccKey.getCurve().getNamedCurve());
                        } catch (GeneralSecurityException e) {
                            throw new FIDO2ServerRuntimeException(
                                    InternalErrorCode.USER_PUBLIC_KEY_INVALID_KEY_SPEC, e);
                        }
                    }
                } else {
                    // error
                    throw new FIDO2ServerRuntimeException(InternalErrorCode.PACKED_ATTESTATION_ALGORITHM_NOT_MATCHED);
                }
            } else if (algorithm.isEdDSAAlgorithm()) {
                if (credentialPublicKey instanceof OctetKey) {
                    OctetKey octetKey = (OctetKey) credentialPublicKey;
                    if (algorithm != octetKey.getAlgorithm()) {
                        // error (not matched)
                        throw new FIDO2ServerRuntimeException(InternalErrorCode.PACKED_ATTESTATION_ALGORITHM_NOT_MATCHED,
                                                              "Alg in statement: " + algorithm + ", in credential public key: " + octetKey.getAlgorithm());
                    } else {
                        // convert
                        try {
                            publicKey = PublicKeyUtil.getEdDSAPublicKey(octetKey.getX(),
                                                                        octetKey.getCurve().getNamedCurve());
                        } catch (GeneralSecurityException e) {
                            throw new FIDO2ServerRuntimeException(
                                    InternalErrorCode.USER_PUBLIC_KEY_INVALID_KEY_SPEC, e);
                        }
                    }
                } else {
                    // error
                    throw new FIDO2ServerRuntimeException(InternalErrorCode.PACKED_ATTESTATION_ALGORITHM_NOT_MATCHED);
                }
            } else {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_COSE_ALGORITHM, "Algorithm " + algorithm);
            }

            // verify signature /w public key, toBeSignedMessage, signature, algorithm
            log.info("Verify signature /w credential public key {}, toBeSignedMessage {}, signature {}, algorithm {}",
                    Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getEncoded()),
                    Base64.getUrlEncoder().withoutPadding().encodeToString(toBeSignedMessage),
                    Base64.getUrlEncoder().withoutPadding().encodeToString(packed.getSig()), algorithm);
            boolean result = SignatureHelper.verifySignature(publicKey, toBeSignedMessage, packed.getSig(), algorithm);

            return AttestationVerificationResult
                    .builder()
                    .success(result)
                    .type(AttestationType.SELF)
                    .trustPath(new ArrayList<>())
                    .format(AttestationStatementFormatIdentifier.PACKED)
                    .build();
        }
    }

    private byte[] extractAaguidFromCredCert(X509Certificate certificate) {
        byte[] extensionAaguidBytes = certificate.getExtensionValue(OID_FIDO_GEN_CE_AAGUID);
        if (extensionAaguidBytes == null
                || extensionAaguidBytes.length == 0) {
            return null;
        }
        try {
            try (ASN1InputStream asn1InputStream = new ASN1InputStream(extensionAaguidBytes)) {
                byte[] derSequenceBytes = ((ASN1OctetString) asn1InputStream
                        .readObject()).getOctets();
                try (ASN1InputStream seqInputStream = new ASN1InputStream(derSequenceBytes)) {
                    return ((ASN1OctetString) seqInputStream.readObject()).getOctets();
                }
            }
        } catch (IOException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.PACKED_ATTESTATION_DATA_DECODING_FAIL, e);
        }
    }
}
