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

package com.linecorp.line.auth.fido.fido2.server.util;

import com.linecorp.line.auth.fido.fido2.common.crypto.Digests;
import com.linecorp.line.auth.fido.fido2.server.attestation.AttestationVerificationResult;
import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;
import com.linecorp.line.auth.fido.fido2.server.exception.FIDO2ServerRuntimeException;
import com.linecorp.line.auth.fido.fido2.server.model.AttestationStatementFormatIdentifier;
import com.linecorp.line.auth.fido.fido2.server.model.AuthenticatorVendor;
import com.linecorp.line.auth.fido.fido2.server.service.VendorSpecificMetadataService;
import com.linecorp.line.auth.fido.uaf.common.metadata.MetadataStatement;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.*;
import java.util.*;

public class CertificateUtil {
    public static List<Certificate> getCertificates(List<byte[]> certificateBytesList) throws CertificateException {
        List<Certificate> certificates = new ArrayList<>();
        for (byte[] certificateBytes : certificateBytesList) {
            certificates.add(getCertificate(certificateBytes));
        }
        return certificates;
    }

    public static List<Certificate> getCertificatesFromStringList(List<String> certificateList) throws CertificateException {
        List<Certificate> certificates = new ArrayList<>();
        for (String certificate : certificateList) {
            byte[] certBytes = Base64.getDecoder().decode(certificate);
            certificates.add(getCertificate(certBytes));
        }
        return certificates;
    }

    public static Certificate getCertificate(byte[] certificateBytes) throws CertificateException {
        return getCertificate(new ByteArrayInputStream(certificateBytes));
    }

    public static Certificate getCertificate(InputStream inputStream) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return certificateFactory.generateCertificate(inputStream);
    }

    public static Certificate getCertificate(String certificate) throws CertificateException {
        byte[] certBytes = Base64.getDecoder().decode(certificate);
        return getCertificate(certBytes);
    }

    public static Set<TrustAnchor> getTrustAnchors(List<String> rootCertificates) throws CertificateException {
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        for (String cert : rootCertificates) {
            byte[] certBytes = Base64.getDecoder().decode(cert);

            X509Certificate certificate = (X509Certificate) getCertificate(certBytes);
            TrustAnchor trustAnchor = new TrustAnchor(certificate, null);
            trustAnchors.add(trustAnchor);
        }

        return trustAnchors;
    }

    public static List<String> getAttestationRootCertificates(VendorSpecificMetadataService vendorSpecificMetadataService, AttestationVerificationResult attestationVerificationResult, List<MetadataStatement> metadataStatementList) {

        if (attestationVerificationResult.getFormat() == AttestationStatementFormatIdentifier.FIDO_U2F) {
            X509Certificate x509 = (X509Certificate) attestationVerificationResult.getTrustPath().get(0);
            String dn = x509.getIssuerDN().getName();

            if (dn.toLowerCase().contains(AuthenticatorVendor.YUBICO.getValue())) {
                return vendorSpecificMetadataService.getAttestationRootCertificates(
                        AuthenticatorVendor.YUBICO);
            } else {
                MetadataStatement metadataStatement = metadataStatementList
                        .stream()
                        .filter(metadataStatementV2 -> metadataStatementV2
                                .getAttestationCertificateKeyIdentifiers()
                                .contains(getU2FKeyId(attestationVerificationResult)))
                        .findFirst().orElseThrow(
                                () -> new FIDO2ServerRuntimeException(
                                        InternalErrorCode.METADATA_NOT_FOUND));
                if (metadataStatement != null) {
                    return metadataStatement.getAttestationRootCertificates();
                }
                return null;
            }
        } else if (attestationVerificationResult.getFormat()
                == AttestationStatementFormatIdentifier.ANDROID_KEY ||
                attestationVerificationResult.getFormat()
                        == AttestationStatementFormatIdentifier.ANDROID_SAFETYNET) {
            // get google root certificates
            return vendorSpecificMetadataService
                    .getAttestationRootCertificates(AuthenticatorVendor.fromValue("google"));
        } else if (attestationVerificationResult.getFormat()
                == AttestationStatementFormatIdentifier.APPLE_ANONYMOUS) {
            return vendorSpecificMetadataService
                    .getAttestationRootCertificates(AuthenticatorVendor.fromValue("apple"));
        }
        return null;
    }


    private static String getU2FKeyId(AttestationVerificationResult attestationVerificationResult) {
        byte[] pubKeyBytes = attestationVerificationResult.getTrustPath().get(0).getPublicKey()
                .getEncoded();
        SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(pubKeyBytes);
        byte[] rawKey = subPubKeyInfo.getPublicKeyData().getBytes();
        byte[] hashed = Digests.sha1(rawKey);
        String keyId = Hex.encodeHexString(hashed);
//        log.info("FIDO U2F Key, Need to find metadata with keyId: {}", keyId);
        return keyId;
    }

    public static CertPath generateCertPath(List<Certificate> certificates) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return certificateFactory.generateCertPath(certificates);
    }
}
