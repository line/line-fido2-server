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

package com.linecorp.line.auth.fido.fido2.server.attestation.apple;

import com.linecorp.line.auth.fido.fido2.common.crypto.Digests;
import com.linecorp.line.auth.fido.fido2.common.server.AttestationType;
import com.linecorp.line.auth.fido.fido2.server.attestation.AttestationVerificationResult;
import com.linecorp.line.auth.fido.fido2.server.attestation.AttestationVerifier;
import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;
import com.linecorp.line.auth.fido.fido2.server.exception.FIDO2ServerRuntimeException;
import com.linecorp.line.auth.fido.fido2.server.helper.CredentialPublicKeyHelper;
import com.linecorp.line.auth.fido.fido2.server.model.AttestationStatement;
import com.linecorp.line.auth.fido.fido2.server.model.AttestationStatementFormatIdentifier;
import com.linecorp.line.auth.fido.fido2.server.model.AuthenticatorData;
import com.linecorp.line.auth.fido.fido2.server.util.CertificateUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

@Slf4j
@Component
public class AppleAnonymousAttestationVerifier implements AttestationVerifier {

    private static final String APPLE_ANONYMOUS_ATTESTATION_OID = "1.2.840.113635.100.8.2";

    @Override
    public AttestationStatementFormatIdentifier getIdentifier() {
        return AttestationStatementFormatIdentifier.APPLE_ANONYMOUS;
    }

    @Override
    public AttestationVerificationResult verify(AttestationStatement attestationStatement, AuthenticatorData authenticatorData, byte[] clientDataHash) {
        AppleAnonymousAttestationStatement appleAnonymous = (AppleAnonymousAttestationStatement) attestationStatement;

        log.info("Prepare nonceToHash");
        byte[] expectedNonceToHash = ByteBuffer
                .allocate(authenticatorData.getBytes().length + clientDataHash.length)
                .put(authenticatorData.getBytes())
                .put(clientDataHash)
                .array();
        log.debug("nonceToHash (b64url enc): {}", Base64.getUrlEncoder().withoutPadding().encodeToString(expectedNonceToHash));

        if (appleAnonymous.getX5c() != null &&
                !appleAnonymous.getX5c().isEmpty()) {
            List<Certificate> certificateList;
            try {
                certificateList = CertificateUtil.getCertificates(appleAnonymous.getX5c());
            } catch (CertificateException e) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.ATTESTATION_CERTIFICATE_ERROR, e);
            }

            X509Certificate certificate = (X509Certificate) certificateList.get(0);
            byte[] expectedNonce = Digests.sha256(expectedNonceToHash);
            ASN1Sequence credCertASN1Sequence = extractASN1Sequence(certificate);
            byte[] certNonce = getNonceFromCredCert(credCertASN1Sequence);

            if (!Arrays.equals(expectedNonce, certNonce)) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.SIGNATURE_VERIFICATION_ERROR);
            }

            byte[] attestedCredPubKey = CredentialPublicKeyHelper.convert(authenticatorData.getAttestedCredentialData().getCredentialPublicKey()).getEncoded();
            byte[] certPubKey = certificate.getPublicKey().getEncoded();

            if (!Arrays.equals(attestedCredPubKey, certPubKey)) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.APPLE_ANONYMOUS_ATTESTATION_PUBLIC_KEY_NOT_MATCHED);
            }

            return AttestationVerificationResult
                    .builder()
                    .success(true)
                    .type(AttestationType.ANON_CA)
                    .trustPath(certificateList)
                    .format(AttestationStatementFormatIdentifier.APPLE_ANONYMOUS)
                    .build();
        }

        throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_ATTESTATION_FORMAT);
    }

    private ASN1Sequence extractASN1Sequence(X509Certificate certificate) {
        byte[] attestationExtensionBytes = certificate.getExtensionValue(APPLE_ANONYMOUS_ATTESTATION_OID);
        if (attestationExtensionBytes == null
                || attestationExtensionBytes.length == 0) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.APPLE_ANONYMOUS_ATTESTATION_DATA_NOT_FOUND, "Couldn't find the apple anonymous attestation extension data.");
        }

        ASN1Sequence decodedSequence;
        try {
            try (ASN1InputStream asn1InputStream = new ASN1InputStream(attestationExtensionBytes)) {
                // The extension contains one object, a sequence, in the
                // Distinguished Encoding Rules (DER)-encoded form. Get the DER
                // bytes.
                byte[] derSequenceBytes = ((ASN1OctetString) asn1InputStream
                        .readObject()).getOctets();
                // Decode the bytes as an ASN1 sequence object.
                try (ASN1InputStream seqInputStream = new ASN1InputStream(derSequenceBytes)) {
                    decodedSequence = (ASN1Sequence) seqInputStream.readObject();
                }
            }
        } catch (IOException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.APPLE_ANONYMOUS_ATTESTATION_DATA_DECODING_FAIL, e);
        }
        return decodedSequence;
    }

    private byte[] getNonceFromCredCert(ASN1Sequence credCertASN1Sequence) {
        DERTaggedObject sequenceObject = (DERTaggedObject) credCertASN1Sequence.getObjectAt(0);
        return ASN1OctetString.getInstance(sequenceObject.getObject()).getOctets();
    }
}
