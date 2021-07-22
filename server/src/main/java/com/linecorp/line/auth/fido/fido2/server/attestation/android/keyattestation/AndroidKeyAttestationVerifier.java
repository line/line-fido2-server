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

package com.linecorp.line.auth.fido.fido2.server.attestation.android.keyattestation;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.NoSuchElementException;

import com.linecorp.line.auth.fido.fido2.server.helper.CredentialPublicKeyHelper;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.springframework.stereotype.Component;

import com.linecorp.line.auth.fido.fido2.server.util.CertificateUtil;
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

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class AndroidKeyAttestationVerifier implements AttestationVerifier {
    private static final String KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17";

    @Override
    public AttestationStatementFormatIdentifier getIdentifier() {
        return AttestationStatementFormatIdentifier.ANDROID_KEY;
    }

    @Override
    public AttestationVerificationResult verify(AttestationStatement attestationStatement, AuthenticatorData authenticatorData,
                                                byte[] clientDataHash) {
        AndroidKeyAttestationStatement androidKey = (AndroidKeyAttestationStatement) attestationStatement;

        // check validity
        if (androidKey.getSig() == null ||
            androidKey.getSig().length == 0 ||
            androidKey.getX5c() == null || androidKey.getX5c().isEmpty()) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_ATTESTATION_FORMAT);
        }

        COSEAlgorithm algorithm;
        try {
            algorithm = COSEAlgorithm.fromValue(androidKey.getAlg());
        } catch (NoSuchElementException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_COSE_ALGORITHM, "Alg " + androidKey.getAlg());
        }


        byte[] toBeSignedMessage = ByteBuffer
                .allocate(authenticatorData.getBytes().length + clientDataHash.length)
                .put(authenticatorData.getBytes())
                .put(clientDataHash)
                .array();

        List<Certificate> certificates;
        try {
            certificates = CertificateUtil.getCertificates(androidKey.getX5c());
        } catch (CertificateException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.ATTESTATION_CERTIFICATE_ERROR, e);
        }

        PublicKey publicKey = certificates.get(0).getPublicKey();

        // verify signature
        boolean result = SignatureHelper
                .verifySignature(publicKey, toBeSignedMessage, androidKey.getSig(), algorithm);

        // verify matching between public key in leaf cert and credential public key
        byte[] publicKeyBytes = publicKey.getEncoded();
        PublicKey credentialPublicKey = CredentialPublicKeyHelper.convert(authenticatorData.getAttestedCredentialData().getCredentialPublicKey());
        byte[] credentialPublicKeyBytes = credentialPublicKey.getEncoded();

        if (!Arrays.equals(publicKeyBytes, credentialPublicKeyBytes)) {
            // should be identical
            throw new FIDO2ServerRuntimeException(
                    InternalErrorCode.ANDROID_KEY_ATTESTATION_PUBLIC_KEY_NOT_MATCHED);
        }

        // verify extension data in attestation certificate
        X509Certificate attestationCertificate = (X509Certificate) certificates.get(0);
        ASN1Sequence sequence = extractASN1Sequence(attestationCertificate);
        KeyDescription keyDescription = getKeyDescription(sequence);

        // check whether attestationChallenge is identical to clientDataHash
        if (!Arrays.equals(clientDataHash, keyDescription.getAttestationChallenge())) {
            throw new FIDO2ServerRuntimeException(
                    InternalErrorCode.ANDROID_KEY_ATTESTATION_ATTESTATION_CHALLENGE_NOT_MATCH_TO_CLIENT_DATA_HASH);
        }

        AuthorizationList authorizationList = null;
        if (keyDescription.getTeeEnforced() != null) {
            authorizationList = keyDescription.getTeeEnforced();
        }

        if (keyDescription.getSoftwareEnforced() != null) {
            authorizationList = keyDescription.getSoftwareEnforced();
        }

        if (authorizationList != null) {
            if (authorizationList.isAllApplications()) {
                // MUST not presented this field, since this key is bound to RP ID
                throw new FIDO2ServerRuntimeException(InternalErrorCode.ANDROID_KEY_ATTESTATION_ATTESTATION_ALL_APPLICATION_SET);
            }

            // TODO: Need to check spec again, spec dealing with android key attestation is weird
        } else {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.ANDROID_KEY_ATTESTATION_CERTIFICATE_INVALID,
                                                  "Authorization list is null");
        }

        return AttestationVerificationResult
                .builder()
                .success(result)
                .type(AttestationType.BASIC)
                .trustPath(certificates)
                .format(AttestationStatementFormatIdentifier.ANDROID_KEY)
                .build();

    }

    private ASN1Sequence extractASN1Sequence(X509Certificate certificate) {
        byte[] attestationExtensionBytes = certificate.getExtensionValue(KEY_DESCRIPTION_OID);
        if (attestationExtensionBytes == null
            || attestationExtensionBytes.length == 0) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.ANDROID_KEY_ATTESTATION_DATA_NOT_FOUND, "Couldn't find the keystore attestation extension data.");
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
            throw new FIDO2ServerRuntimeException(InternalErrorCode.ANDROID_KEY_ATTESTATION_DATA_DECODING_FAIL, e);
        }
        return decodedSequence;
    }

    private KeyDescription getKeyDescription(ASN1Sequence sequence) {
        KeyDescription.KeyDescriptionBuilder builder = KeyDescription.builder();
        //attestation version
        ASN1Integer asn1Integer = ASN1Integer.getInstance(sequence.getObjectAt(KeyDescriptionIndex.ATTESTATION_VERSION_INDEX));
        int attestationVersion = bigIntegerToInt(asn1Integer.getValue());
        //attestation security level
        SecurityLevel attestationSecurityLevel = SecurityLevel
                .fromValue(bigIntegerToInt(ASN1Enumerated.getInstance(sequence.getObjectAt(KeyDescriptionIndex.ATTESTATION_SECURITY_LEVEL_INDEX)).getValue()));
        //keymaster version
        asn1Integer = ASN1Integer.getInstance(sequence.getObjectAt(KeyDescriptionIndex.KEYMASTER_VERSION_INDEX));
        int keymasterVersion = bigIntegerToInt(asn1Integer.getValue());
        //keymaster security level
        SecurityLevel keymasterSecurityLevel = SecurityLevel
                .fromValue(bigIntegerToInt(ASN1Enumerated.getInstance(sequence.getObjectAt(KeyDescriptionIndex.KEYMASTER_SECURITY_LEVEL_INDEX)).getValue()));
        //attestation challenge
        byte[] attestationChallenge = ASN1OctetString.getInstance(sequence.getObjectAt(KeyDescriptionIndex.ATTESTATION_CHALLENGE_INDEX)).getOctets();
        //softwareEnforced
        AuthorizationList softwareEnforced = null;
        ASN1Encodable[] asn1Encodables = ((ASN1Sequence) sequence.getObjectAt(KeyDescriptionIndex.SW_ENFORCED_INDEX)).toArray();
        if (asn1Encodables != null && asn1Encodables.length > 0) {
            softwareEnforced = getAuthorizationList(asn1Encodables);
        }
        //teeEnforced
        AuthorizationList teeEnforced = null;
        asn1Encodables = ((ASN1Sequence) sequence.getObjectAt(KeyDescriptionIndex.TEE_ENFORCED_INDEX)).toArray();
        if (asn1Encodables != null && asn1Encodables.length > 0) {
            teeEnforced = getAuthorizationList(asn1Encodables);
        }

        return builder.attestationVersion(attestationVersion)
                      .attestationSecurityLevel(attestationSecurityLevel)
                      .keymasterVersion(keymasterVersion)
                      .keymasterSecurityLevel(keymasterSecurityLevel)
                      .attestationChallenge(attestationChallenge)
                      .softwareEnforced(softwareEnforced)
                      .teeEnforced(teeEnforced)
                      .build();
    }

    private AuthorizationList getAuthorizationList(ASN1Encodable[] asn1Encodables) {
        AuthorizationList authorizationList = new AuthorizationList();
        for (ASN1Encodable asn1Encodable : asn1Encodables) {
            ASN1TaggedObject entry = (ASN1TaggedObject) asn1Encodable;

            switch (entry.getTagNo()) {
                case AuthorizationListTags.KM_TAG_PURPOSE: {
                    List<Integer> purposeList = new ArrayList<>();
                    ASN1Encodable[] purposes = ASN1Set.getInstance(entry.getObject()).toArray();
                    for (ASN1Encodable purpose : purposes) {
                        purposeList.add(bigIntegerToInt(ASN1Integer.getInstance(purpose).getValue()));
                    }
                    authorizationList.setPurpose(purposeList);
                    break;
                }
                case AuthorizationListTags.KM_TAG_ALGORITHM: {
                    int algorithm = bigIntegerToInt(ASN1Integer.getInstance(entry.getObject()).getValue());
                    authorizationList.setAlgorithm(algorithm);
                    break;
                }
                case AuthorizationListTags.KM_TAG_KEY_SIZE: {
                    int keySize = bigIntegerToInt(ASN1Integer.getInstance(entry.getObject()).getValue());
                    authorizationList.setKeySize(keySize);
                    break;
                }
                case AuthorizationListTags.KM_TAG_DIGEST: {
                    List<Integer> digestList = new ArrayList<>();
                    ASN1Encodable[] digests = ASN1Set.getInstance(entry.getObject()).toArray();
                    for (ASN1Encodable digest : digests) {
                        digestList.add(bigIntegerToInt(ASN1Integer.getInstance(digest).getValue()));
                    }
                    authorizationList.setDigest(digestList);
                    break;
                }
                case AuthorizationListTags.KM_TAG_PADDING: {
                    List<Integer> paddingList = new ArrayList<>();
                    ASN1Encodable[] paddings = ASN1Set.getInstance(entry.getObject()).toArray();
                    for (ASN1Encodable padding : paddings) {
                        paddingList.add(bigIntegerToInt(ASN1Integer.getInstance(padding).getValue()));
                    }
                    authorizationList.setPadding(paddingList);
                    break;
                }
                case AuthorizationListTags.KM_TAG_EC_CURVE: {
                    int ecCurve = bigIntegerToInt(ASN1Integer.getInstance(entry.getObject()).getValue());
                    authorizationList.setEcCurve(ecCurve);
                    break;
                }
                case AuthorizationListTags.KM_TAG_RSA_PUBLIC_EXPONENT: {
                    int rsaPublicExponent = bigIntegerToInt(ASN1Integer.getInstance(entry.getObject()).getValue());
                    authorizationList.setRsaPublicExponent(rsaPublicExponent);
                    break;
                }
                case AuthorizationListTags.KM_TAG_ACTIVE_DATETIME: {
                    int activeDateTime = bigIntegerToInt(ASN1Integer.getInstance(entry.getObject()).getValue());
                    authorizationList.setActiveDateTime(activeDateTime);
                    break;
                }
                case AuthorizationListTags.KM_TAG_ORIGINATION_EXPIRE_DATETIME: {
                    int originationExpireDateTime = bigIntegerToInt(ASN1Integer.getInstance(entry.getObject()).getValue());
                    authorizationList.setOriginationExpireDateTime(originationExpireDateTime);
                    break;
                }
                case AuthorizationListTags.KM_TAG_USAGE_EXPIRE_DATETIME: {
                    int usageExpireDateTime = bigIntegerToInt(ASN1Integer.getInstance(entry.getObject()).getValue());
                    authorizationList.setUsageExpireDateTime(usageExpireDateTime);
                    break;
                }
                case AuthorizationListTags.KM_TAG_NO_AUTH_REQUIRED: {
                    authorizationList.setNoAuthRequired(true);
                    break;
                }
                case AuthorizationListTags.KM_TAG_USER_AUTH_TYPE: {
                    int userAuthType = bigIntegerToInt(ASN1Integer.getInstance(entry.getObject()).getValue());
                    authorizationList.setUserAuthType(userAuthType);
                    break;
                }
                case AuthorizationListTags.KM_TAG_AUTH_TIMEOUT: {
                    int authTimeout = bigIntegerToInt(ASN1Integer.getInstance(entry.getObject()).getValue());
                    authorizationList.setAuthTimeout(authTimeout);
                    break;
                }
                case AuthorizationListTags.KM_TAG_ALLOW_WHILE_ON_BODY: {
                    authorizationList.setAllowWhileOnBody(true);
                    break;
                }
                case AuthorizationListTags.KM_TAG_ALL_APPLICATIONS: {
                    authorizationList.setAllApplications(true);
                    break;
                }
                case AuthorizationListTags.KM_TAG_APPLICATION_ID: {
                    byte[] applicationId = ASN1OctetString.getInstance(entry.getObject()).getOctets();
                    authorizationList.setApplicationId(applicationId);
                    break;
                }
                case AuthorizationListTags.KM_TAG_CREATION_DATETIME: {
                    int creationDateTime = bigIntegerToInt(ASN1Integer.getInstance(entry.getObject()).getValue());
                    authorizationList.setCreationDateTime(creationDateTime);
                    break;
                }
                case AuthorizationListTags.KM_TAG_ORIGIN: {
                    int origin = bigIntegerToInt(ASN1Integer.getInstance(entry.getObject()).getValue());
                    authorizationList.setOrigin(origin);
                    break;
                }
                case AuthorizationListTags.KM_TAG_ROLLBACK_RESISTANT: {
                    authorizationList.setRollbackResistant(true);
                    break;
                }
                case AuthorizationListTags.KM_TAG_ROOT_OF_TRUST: {
                    RootOfTrust rootOfTrust = new RootOfTrust();
                    ASN1Sequence sequence = (ASN1Sequence) entry.getObject();
                    //verifiedBootKey
                    byte[] verifiedBootKey = ASN1OctetString.getInstance(sequence.getObjectAt(0)).getOctets();
                    //deviceLocked
                    boolean deviceLocked = ASN1Boolean.getInstance(sequence.getObjectAt(1)).isTrue();
                    //verifiedBootState

                    VerifiedBootState verifiedBootState = VerifiedBootState
                            .fromValue(bigIntegerToInt(ASN1Enumerated.getInstance(sequence.getObjectAt(2)).getValue()));

                    rootOfTrust.setVerifiedBootKey(verifiedBootKey);
                    rootOfTrust.setDeviceLocked(deviceLocked);
                    rootOfTrust.setVerifiedBootState(verifiedBootState);
                    authorizationList.setRootOfTrust(rootOfTrust);
                    break;
                }
                case AuthorizationListTags.KM_TAG_OS_VERSION: {
                    int osVersion = bigIntegerToInt(ASN1Integer.getInstance(entry.getObject()).getValue());
                    authorizationList.setOsVersion(osVersion);
                    break;
                }
                case AuthorizationListTags.KM_TAG_PATCHLEVEL: {
                    int osPatchLevel = bigIntegerToInt(ASN1Integer.getInstance(entry.getObject()).getValue());
                    authorizationList.setOsPatchLevel(osPatchLevel);
                    break;
                }
                case AuthorizationListTags.KM_TAG_ATTESTATION_CHALLENGE: {
                    int attestationChallenge = bigIntegerToInt(ASN1Integer.getInstance(entry.getObject()).getValue());
                    authorizationList.setAttestationChallenge(attestationChallenge);
                    break;
                }
                case AuthorizationListTags.KM_TAG_ATTESTATION_APPLICATION_ID: {
                    byte[] attestationApplicationId = ASN1OctetString.getInstance(entry.getObject()).getOctets();
                    authorizationList.setAttestationApplicationId(attestationApplicationId);
                    break;
                }
                default: {
                    break;
                }
            }
        }

        return authorizationList;
    }

    private int bigIntegerToInt(BigInteger bigInt) {
        return bigInt.intValue();
    }
}
