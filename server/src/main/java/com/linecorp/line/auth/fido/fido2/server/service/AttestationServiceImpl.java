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

package com.linecorp.line.auth.fido.fido2.server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.linecorp.line.auth.fido.fido2.common.AuthenticatorSelectionCriteria;
import com.linecorp.line.auth.fido.fido2.common.UserVerificationRequirement;
import com.linecorp.line.auth.fido.fido2.common.crypto.Digests;
import com.linecorp.line.auth.fido.fido2.common.server.AttestationType;
import com.linecorp.line.auth.fido.fido2.common.server.ServerAuthenticatorAttestationResponse;
import com.linecorp.line.auth.fido.fido2.server.attestation.AttestationVerificationResult;
import com.linecorp.line.auth.fido.fido2.server.attestation.AttestationVerifierFactory;
import com.linecorp.line.auth.fido.fido2.server.attestation.android.keyattestation.AdditionalRevokeChecker;
import com.linecorp.line.auth.fido.fido2.server.attestation.android.keyattestation.RevokeCheckerClient;
import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;
import com.linecorp.line.auth.fido.fido2.server.exception.FIDO2ServerRuntimeException;
import com.linecorp.line.auth.fido.fido2.server.model.AttestationObject;
import com.linecorp.line.auth.fido.fido2.server.model.AttestationStatementFormatIdentifier;
import com.linecorp.line.auth.fido.fido2.server.util.AaguidUtil;
import com.linecorp.line.auth.fido.fido2.server.util.CertPathUtil;
import com.linecorp.line.auth.fido.fido2.server.util.CertificateUtil;
import com.linecorp.line.auth.fido.uaf.common.metadata.MetadataStatement;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;

@Slf4j
@Service
public class AttestationServiceImpl implements AttestationService {

    private final MetadataService metadataService;
    private final VendorSpecificMetadataService vendorSpecificMetadataService;
    private final AttestationVerifierFactory attestationVerifierFactory;
    private final RevokeCheckerClient revokeCheckerClient;

    @Value("${fido.fido2.accept-unregistered-authenticators}")
    private boolean acceptUnregisteredAuthenticators;

    @Autowired
    public AttestationServiceImpl(MetadataService metadataService, VendorSpecificMetadataService vendorSpecificMetadataService, AttestationVerifierFactory attestationVerifierFactory, RevokeCheckerClient revokeCheckerClient) {
        this.metadataService = metadataService;
        this.vendorSpecificMetadataService = vendorSpecificMetadataService;
        this.attestationVerifierFactory = attestationVerifierFactory;
        this.revokeCheckerClient = revokeCheckerClient;
    }

    @Override
    public AttestationVerificationResult verifyAttestation(byte[] clientDataHsh, AttestationObject attestationObject) {
        // verify attStmt
        log.info("Verify attStmt with format {}", attestationObject.getFmt());
        AttestationVerificationResult attestationVerificationResult =
                attestationVerifierFactory
                        .getVerifier(attestationObject.getFmt())
                        .verify(attestationObject.getAttStmt(), attestationObject.getAuthData(), clientDataHsh);
        log.info("Attestation verification result {}", attestationVerificationResult);
        return attestationVerificationResult;
    }

    @Override
    public AttestationObject getAttestationObject(ServerAuthenticatorAttestationResponse attestationResponse) {
        byte[] attestationObjectBytes = Base64
                .getUrlDecoder()
                .decode(attestationResponse.getAttestationObject());

        // perform CBOR decoding
        log.info("Perform CBOR decoding of attestationObject");
        CBORFactory cborFactory = new CBORFactory();
        ObjectMapper objectMapper = new ObjectMapper(cborFactory);
        AttestationObject attestationObject;
        try {
            attestationObject = objectMapper.readValue(attestationObjectBytes, AttestationObject.class);
        } catch (IOException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_FORMAT_ATTESTATION_OBJECT, e);
        }
        log.debug("Decoded AttestationObject {}", attestationObject);
        return attestationObject;
    }

    @Override
    public void attestationObjectValidationCheck(String rpId, AuthenticatorSelectionCriteria authenticatorSelection, AttestationObject attestationObject) {
        // verify attestationObject.authData.attestedCredentialData
        if (attestationObject.getAuthData().getAttestedCredentialData() == null) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.CREDENTIAL_NOT_INCLUDED);
        }

        // verify RP ID (compare with SHA256 hash or RP ID)
        log.info("Verify hash of RP ID with rpIdHash in authData");
        byte[] rpIdHash = Digests.sha256(rpId.getBytes(StandardCharsets.UTF_8));
        if (!Arrays.equals(attestationObject.getAuthData().getRpIdHash(), rpIdHash)) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.RPID_HASH_NOT_MATCHED);
        }

        // verify user present flag
        log.info("Verify user present flag. Should be set");
        if (!attestationObject.getAuthData().isUserPresent()) {
            // Temporary comment out for Android chrome testings
//            throw new FIDO2ServerRuntimeException(InternalErrorCode.USER_PRESENCE_FLAG_NOT_SET);
        }

        // verify user verification
        log.info("Verify user verification flag if user verification required");
        if (authenticatorSelection != null &&
                authenticatorSelection.getUserVerification() != null &&
                authenticatorSelection.getUserVerification() == UserVerificationRequirement.REQUIRED &&
                !attestationObject.getAuthData().isUserVerified()) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.USER_VERIFICATION_FLAG_NOT_SET);
        }
    }

    @Override
    public void verifyAttestationCertificate(AttestationObject attestationObject, AttestationVerificationResult attestationVerificationResult) {
        // verify trustworthiness
        // check the attestation certificate chained up to root certificates
        // if fails, SHOULD reject the registration
        log.info("Verify trustworthiness of chain");

        byte[] aaguid = attestationObject.getAuthData().getAttestedCredentialData().getAaguid();
        MetadataStatement metadataStatement = null;
        if (aaguid != null && !Arrays.equals(aaguid, new byte[16])) {   // aaguid value for u2f is zeroed
            String aaguidString = AaguidUtil.convert(aaguid);
            log.debug("Valid AAGUID: {}", aaguidString);
            metadataStatement = metadataService.getMetadataStatementWithAaguid(aaguidString);
        } else {
            log.debug("empty AAGUID");
        }
        List<String> attestationRootCertificates;
        if (metadataStatement != null) {
            attestationRootCertificates = metadataStatement.getAttestationRootCertificates();
        } else {
            attestationRootCertificates = CertificateUtil.getAttestationRootCertificates(vendorSpecificMetadataService, attestationVerificationResult, metadataService.getAllU2FMetadataStatements());
        }
        // format specific handling
        log.debug("attestation format: {}", attestationVerificationResult.getFormat());

        // set attestation root certificate with metadata or vendor specific data
        // or skip getting metadata
        if (!acceptUnregisteredAuthenticators) {    // throw an error if there is no metadata
            if (attestationRootCertificates == null) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.METADATA_NOT_FOUND);
            }
        }

        if (attestationRootCertificates != null) {
            verifyCertificateChainOfTrust(attestationObject, attestationVerificationResult, attestationRootCertificates);
        }
    }

    private void verifyCertificateChainOfTrust(AttestationObject attestationObject, AttestationVerificationResult attestationVerificationResult, List<String> attestationRootCertificates) {
        try {
            Set<TrustAnchor> trustAnchors = CertificateUtil.getTrustAnchors(attestationRootCertificates);

            boolean matched = isTopIntermediateCertificateSameWithRootCertificates(attestationVerificationResult, trustAnchors, attestationVerificationResult.getTrustPath().size());

            if (isSelfSignedAttestation(matched, attestationVerificationResult.getType()
                    == AttestationType.BASIC, attestationVerificationResult.getTrustPath().size() == 1)) {
                //Doesn't need to verify cert chain for Self Signed Attestation.
                return;
            }

            if (matched) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.CERTIFICATE_PATH_VALIDATION_FAIL,
                        "Top intermediate certificate includes one of attestation root certificates");
            }

            boolean enableRevocation = hasCRLDistPointForRevokeCheck(attestationVerificationResult);

            if (attestationObject.getFmt() == AttestationStatementFormatIdentifier.ANDROID_KEY) {
                if (AdditionalRevokeChecker.hasAndroidKeyAttestationRevokedCert(revokeCheckerClient,attestationVerificationResult.getTrustPath())) {
                    throw new FIDO2ServerRuntimeException(InternalErrorCode.CERTIFICATE_PATH_VALIDATION_FAIL);
                }
            }

            boolean result = CertPathUtil.validate(attestationVerificationResult.getTrustPath(),
                    trustAnchors, enableRevocation);
            log.debug("trust path: " + attestationVerificationResult.getTrustPath());
            log.debug("trust anchors: " + trustAnchors);
            log.debug("validation result: " + result);

            if (!result) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.CERTIFICATE_PATH_VALIDATION_FAIL);
            }

        } catch (GeneralSecurityException | IOException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.CRYPTO_OPERATION_EXCEPTION,
                    "Cert path validation algorithm parameter error", e);
        }
    }

    private boolean hasCRLDistPointForRevokeCheck(AttestationVerificationResult attestationVerificationResult) throws IOException {
        log.debug("num certs in chain:" + attestationVerificationResult.getTrustPath().size());
        X509Certificate leafCert = (X509Certificate) attestationVerificationResult.getTrustPath().get(0);
        log.debug("**** leaf cert subject: " + leafCert.getSubjectDN());
        log.debug("**** leaf cert issuer: " + leafCert.getIssuerDN());

        byte[] cdpExt = leafCert.getExtensionValue(Extension.cRLDistributionPoints.getId());
        CRLDistPoint cdp = null;
        if (cdpExt != null) {
            cdp = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(cdpExt));
        }
        log.debug(String.format("***** SubjectDN: [%s], CDP: [%s]", leafCert.getSubjectDN(),
                cdp == null ? "<null>" : cdp));
        boolean enableRevocation = cdpExt != null;
        log.debug("enable revocation: " + enableRevocation);
        return enableRevocation;
    }

    private boolean isTopIntermediateCertificateSameWithRootCertificates(AttestationVerificationResult attestationVerificationResult, Set<TrustAnchor> trustAnchors, int size) {
        // check top intermediate certificate is included in attestation root certificates
        boolean matched = trustAnchors
                .stream()
                .anyMatch(e -> {
                    try {
                        return Arrays.equals(e.getTrustedCert().getEncoded(),
                                attestationVerificationResult.getTrustPath().get(size - 1)
                                        .getEncoded());
                    } catch (CertificateEncodingException e1) {
                        return false;
                    }
                });
        return matched;
    }

    private boolean isSelfSignedAttestation(boolean matched, boolean isBasicAttestationType, boolean hasOnlyOneTrustPath) {
        return matched && isBasicAttestationType && hasOnlyOneTrustPath;
    }
}
