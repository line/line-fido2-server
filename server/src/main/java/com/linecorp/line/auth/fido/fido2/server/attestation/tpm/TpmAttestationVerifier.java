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

package com.linecorp.line.auth.fido.fido2.server.attestation.tpm;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.springframework.stereotype.Component;

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
import com.linecorp.line.auth.fido.fido2.server.util.CertificateUtil;
import com.linecorp.line.auth.fido.fido2.server.util.UnsignedUtil;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class TpmAttestationVerifier implements AttestationVerifier {
    @Override
    public AttestationStatementFormatIdentifier getIdentifier() {
        return AttestationStatementFormatIdentifier.TPM;
    }

    @Override
    public AttestationVerificationResult verify(AttestationStatement attestationStatement, AuthenticatorData authenticatorData,
                                                byte[] clientDataHash) {
        final long TPM_GENERATED_VALUE = 0xff544347L;
        final String OID_FIDO_GEN_CE_AAGUID = "1.3.6.1.4.1.45724.1.1.4";
        TpmAttestationStatement tpm = (TpmAttestationStatement) attestationStatement;

        if (tpm.getEcdaaKeyId() != null) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.ECDAA_ALGORITHM_NOT_SUPPORTED);
        }

        // check validity
        if (tpm.getSig() == null ||
                tpm.getSig().length == 0 ||
                tpm.getCertInfo() == null ||
                tpm.getCertInfo().length == 0 ||
                tpm.getPubArea() == null ||
                tpm.getPubArea().length == 0 ||
                ((tpm.getEcdaaKeyId() == null || tpm.getEcdaaKeyId().length == 0) &&
                        (tpm.getX5c() == null || tpm.getX5c().isEmpty()))) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_ATTESTATION_FORMAT);
        }

        COSEAlgorithm algorithm;
        try {
            algorithm = COSEAlgorithm.fromValue(tpm.getAlg());
        } catch (NoSuchElementException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_COSE_ALGORITHM, "Alg " + tpm.getAlg());
        }

        boolean result = false;

        byte[] attToBeSigned = ByteBuffer
                .allocate(authenticatorData.getBytes().length + clientDataHash.length)
                .put(authenticatorData.getBytes())
                .put(clientDataHash)
                .array();

        byte[] certInfoBytes = tpm.getCertInfo();
        byte[] pubAreaBytes = tpm.getPubArea();

        CertInfo certInfo;
        PubArea pubArea;
        try {
            certInfo = TpmParser.parseCertInfo(certInfoBytes);
            pubArea = TpmParser.parsePubArea(pubAreaBytes);
        } catch (IOException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.TPM_ATTESTATION_DATA_INVALID, e);
        }


        // validate certInfo first


        // 1. verify magic
        long magic = UnsignedUtil.readUINT32BE(certInfo.getMagic());

        if (TPM_GENERATED_VALUE != magic) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.TPM_ATTESTATION_CERTINFO_MAGIC_NOT_MATCHED);
        }

        // 2. verify type
        if (TpmSt.ATTEST_CERTIFY != certInfo.getType()) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.TPM_ATTESTATION_CERTINFO_TYPE_NOT_MATCHED);
        }

        // 3. verify extraData
        // get hash algorithm first
        String hashAlgorithmName = algorithm.getHashAlgorithm();
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance(hashAlgorithmName);
        } catch (NoSuchAlgorithmException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.TPM_ATTESTATION_INVALID_HASH_ALGORITHM, e);
        }
        byte[] digest = messageDigest.digest(attToBeSigned);
        if (!Arrays.equals(digest, certInfo.getExtraData())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.TPM_ATTESTATION_CERTINFO_EXTRADATA_NOT_MATCHED);
        }
        // 4. verify attested
        AttestedName attestedName = certInfo.getAttestedName();
        // get pubAreaHash /w alg stated in attested name
        try {
            messageDigest = MessageDigest.getInstance(attestedName.getName().getAlgorithmName());
        } catch (NoSuchAlgorithmException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.TPM_ATTESTATION_INVALID_HASH_ALGORITHM, e);
        }
        byte[] pubAreaHash = messageDigest.digest(pubAreaBytes);
        // compare pubAreaHash /w hash in attested name
        if (!Arrays.equals(pubAreaHash, attestedName.getHash())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.TPM_ATTESTATION_CERTINFO_PUBAREA_HASH_NOT_MATCHED);
        }

        // 5. check credential public key in authData /w pubArea unique
        CredentialPublicKey credentialPublicKey = authenticatorData.getAttestedCredentialData().getCredentialPublicKey();
        if (credentialPublicKey instanceof ECCKey) {
            byte[] x = ((ECCKey) credentialPublicKey).getX();
            byte[] y = ((ECCKey) credentialPublicKey).getY();
            byte[] key = ByteBuffer.allocate(x.length + y.length)
                    .put(x)
                    .put(y)
                    .array();

            if (!Arrays.equals(pubArea.getUnique(), key)) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.TPM_ATTESTATION_CERTINFO_PUBAREA_UNIQUE_NOT_MATCH_TO_CREDENTIAL_PUBKEY);
            }
        } else {
            byte[] n = ((RSAKey) credentialPublicKey).getN();
            if (!Arrays.equals(pubArea.getUnique(), n)) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.TPM_ATTESTATION_CERTINFO_PUBAREA_UNIQUE_NOT_MATCH_TO_CREDENTIAL_PUBKEY);
            }
        }

        // 6-1. not ECDAA (AttCA)
        if (tpm.getX5c() != null &&
            !tpm.getX5c().isEmpty()) {
            List<Certificate> certificateList;
            try {
                certificateList = CertificateUtil.getCertificates(tpm.getX5c());
            } catch (CertificateException e) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.ATTESTATION_CERTIFICATE_ERROR, e);
            }

            X509Certificate aikCert = (X509Certificate) certificateList.get(0);

            // verify aikCert to meet the requirements
            verifyTpmAikCert(aikCert);

            // check extension (1.3.6.1.4.1.45724.1.1.4) (MUST be matched to AAGUID)
            // TODO: Need to check
//                byte[] extensionBytes = aikCert.getExtensionValue(OID_FIDO_GEN_CE_AAGUID);
//                if (!Arrays.equals(extensionBytes, authenticatorData.getAttestedCredentialData().getAaguid())) {
//
//                }

            // verify signature
            PublicKey publicKey = aikCert.getPublicKey();
            result = SignatureHelper.verifySignature(publicKey, tpm.getCertInfo(), tpm.getSig(), algorithm);

            return AttestationVerificationResult
                    .builder()
                    .success(result)
                    .type(AttestationType.ATTESTATION_CA)
                    .trustPath(certificateList)
                    .format(AttestationStatementFormatIdentifier.TPM)
                    .build();
        } else {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.TPM_ATTESTATION_DATA_INVALID,
                    "attestation type is not AttCA");
        }
    }

    private void verifyTpmAikCert(X509Certificate aikCert) {
        final String OID_TCG_KP_AIK_CERTIFICATE  = "2.23.133.8.3";
        final ASN1ObjectIdentifier OCSP_ACCESS_METHOD = X509ObjectIdentifiers.ocspAccessMethod;
        final ASN1ObjectIdentifier CRL_ACCESS_METHOD = X509ObjectIdentifiers.crlAccessMethod;
        final String OID_TCG_AT_TPM_MANUFACTURER = "2.23.133.2.1";
        final String OID_TCG_AT_TPM_MODEL = "2.23.133.2.2";
        final String OID_TCG_AT_TPM_VERSION = "2.23.133.2.3";

        log.info("AIK Cert Information");
        log.info(aikCert.toString());

        try {
            // check version (MUST be set to 3)
            if (aikCert.getVersion() != 3) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.TPM_ATTESTATION_CERTIFICATE_VERSION_INVALID);
            }

            // check subject field (MUST be set to empty)
            if (!aikCert.getSubjectX500Principal().getName().isEmpty()) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.TPM_ATTESTATION_CERTIFICATE_SUBJECT_FIELD_INVALID);
            }

            // check san (subject alternative name) extension (MUST be set as defined TPM)
            Collection<List<?>> subjectAltNames = aikCert.getSubjectAlternativeNames();
            if (subjectAltNames == null) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.TPM_ATTESTATION_CERTIFICATE_SAN_INVALID);
            }

            Iterator itAltNames  = subjectAltNames.iterator();

            TpmSubjectAlternativeName.TpmSubjectAlternativeNameBuilder builder =
                    TpmSubjectAlternativeName.builder();
            while(itAltNames.hasNext()) {
                List extensionEntry = (List) itAltNames.next();
                Object name = extensionEntry.get(1);

                X500Principal principal = new X500Principal((String) name);
                X500Name x500Name = new X500Name(principal.getName());
                RDN[] rdns = x500Name.getRDNs();
                AttributeTypeAndValue[] atVs = rdns[0].getTypesAndValues();

                for (AttributeTypeAndValue atv : atVs) {
                    switch (atv.getType().getId()) {
                        case OID_TCG_AT_TPM_MANUFACTURER: {
                            String atvValue = atv.getValue().toASN1Primitive().toString();
                            String value = atvValue.substring(3);
                            long manufacturer = Long.parseLong(value, 16);
                            builder.manufacturer(TpmCapVendorId.fromValue(manufacturer));
                            break;
                        }
                        case OID_TCG_AT_TPM_MODEL:
                            builder.partNumber(atv.getValue().toASN1Primitive().toString());
                            break;
                        case OID_TCG_AT_TPM_VERSION: {
                            String atvValue = atv.getValue().toASN1Primitive().toString();
                            String value = atvValue.substring(3);
                            builder.firmwareVersion(value);
                            break;
                        }
                    }
                }
            }

            TpmSubjectAlternativeName alternativeName = builder.build();
            log.info("TPM Subject Alternative name: {}", alternativeName);

            // check extended key usage extension (MUST contain tcg-kp-AIKCertificate oid)
            List<String> extendedKeyUsage = aikCert.getExtendedKeyUsage();
            if (!extendedKeyUsage.contains(OID_TCG_KP_AIK_CERTIFICATE)) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.TPM_ATTESTATION_CERTIFICATE_EXTENDED_KEY_USAGE_INVALID);
            }

            // check basic constraint extension (MUST have CA component and set to false)
            if (aikCert.getBasicConstraints() != -1) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.TPM_ATTESTATION_CERTIFICATE_BASIC_CONSTRAINTS_INVALID);
            }

            // check AIA (authority information access) extension (id-ad-ocsp and CRL distribution point extension are both optional)
            byte[] authInfoAccessExtensionValue = aikCert.getExtensionValue(
                    Extension.authorityInfoAccess.getId());

            log.info("AIA extension info (Optional)");
            AccessDescription[] accessDescriptions = getAccessDescriptions(authInfoAccessExtensionValue);
            if (accessDescriptions != null) {
                for (AccessDescription accessDescription : accessDescriptions) {

                    if (accessDescription.getAccessMethod().equals(OCSP_ACCESS_METHOD)) {
                        log.info("AIA: OCSP enabled");
                    }

                    if (accessDescription.getAccessMethod().equals(CRL_ACCESS_METHOD)) {
                        log.info("AIA: CRL enabled");
                    }

                    GeneralName gn = accessDescription.getAccessLocation();
                    if (gn.getTagNo() != GeneralName.uniformResourceIdentifier) {
                        continue;
                    }

                    DERIA5String str = (DERIA5String) ((DERTaggedObject) gn.toASN1Primitive()).getObject();
                    log.info("Access Location: {}", str.getString());
                }
            }


        } catch (CertificateParsingException | IOException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.TPM_ATTESTATION_CERTIFICATE_INVALID, e);
        }

    }

    private AccessDescription[] getAccessDescriptions(byte[] authInfoAccessExtensionValue) throws IOException {
        if (null == authInfoAccessExtensionValue) {
            return null;
        }

        ASN1InputStream ais1 = null;
        ASN1InputStream ais2 = null;
        try {

            ByteArrayInputStream bais = new ByteArrayInputStream(authInfoAccessExtensionValue);
            ais1 = new ASN1InputStream(bais);
            DEROctetString oct = (DEROctetString) ais1.readObject();
            ais2 = new ASN1InputStream(oct.getOctets());
            AuthorityInformationAccess
                    authorityInformationAccess = AuthorityInformationAccess.getInstance(ais2.readObject());

            return authorityInformationAccess.getAccessDescriptions();

        } finally {
            ais1.close();
            ais2.close();
        }
    }
}
