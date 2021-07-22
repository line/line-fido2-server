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

import com.linecorp.line.auth.fido.fido2.server.util.UnsignedUtil;

public class TpmParser {
    public static CertInfo parseCertInfo(byte[] certInfo) throws IOException {
        byte[] magicBytes = new byte[4];
        byte[] typeBytes = new byte[2];
        byte[] qualifiedSignerLengthBytes = new byte[2];
        byte[] extraDataLengthBytes = new byte[2];
        byte[] extraDataBytes = null;  // variable length
        byte[] clockInfoBytes = new byte[17];
        byte[] firmwareVersionBytes = new byte[8];
        byte[] attestedNameLengthBytes = new byte[2];
        byte[] attestedNameBytes;   // variable length
        byte[] attestedQualifiedNameLengthBytes = new byte[2];
        byte[] attestedQualifiedNameBytes;  // variable length

        AttestedName attestedName = null;

        ByteArrayInputStream inputStream = new ByteArrayInputStream(certInfo);
        inputStream.read(magicBytes);   // read magic
        inputStream.read(typeBytes);    // read type
        inputStream.read(qualifiedSignerLengthBytes);

        // ignore and skip qualified signer
        int qualifiedSignerLength = UnsignedUtil.readUINT16BE(qualifiedSignerLengthBytes);
        if (qualifiedSignerLength > 0) {
            inputStream.skip(qualifiedSignerLength);
        }
        // read extra data
        inputStream.read(extraDataLengthBytes);
        int extraDataLength = UnsignedUtil.readUINT16BE(extraDataLengthBytes);
        if (extraDataLength > 0) {
            extraDataBytes = new byte[extraDataLength];
            inputStream.read(extraDataBytes);
        }
        inputStream.read(clockInfoBytes);   // read clock info
        ClockInfo clockInfo = parseClockInfo(clockInfoBytes);
        inputStream.read(firmwareVersionBytes); // read firmware version
        // read attested name
        inputStream.read(attestedNameLengthBytes);
        int attestedNameLength = UnsignedUtil.readUINT16BE(attestedNameLengthBytes);
        if (attestedNameLength > 0) {
            attestedNameBytes = new byte[attestedNameLength];
            inputStream.read(attestedNameBytes);

            // parse attested name
            attestedName = parseAttestedName(attestedNameBytes);

        }
        // read attested qualified name
        inputStream.read(attestedQualifiedNameLengthBytes);
        int attestedQualifiedNameLength = UnsignedUtil.readUINT16BE(attestedQualifiedNameLengthBytes);
        if (attestedQualifiedNameLength > 0) {
            attestedQualifiedNameBytes = new byte[attestedQualifiedNameLength];
            inputStream.read(attestedQualifiedNameBytes);
        }

        return CertInfo
                .builder()
                .magic(magicBytes)
                .type(TpmSt.fromValue(UnsignedUtil.readUINT16BE(typeBytes)))
                .extraData(extraDataBytes)
                .clockInfo(clockInfo)
                .firmwareVersion(firmwareVersionBytes)
                .attestedName(attestedName)
                .build();

    }

    public static PubArea parsePubArea(byte[] pubArea) throws IOException {
        byte[] typeBytes = new byte[2];
        byte[] nameAlgBytes = new byte[2];
        byte[] objectAttributesBytes = new byte[4];
        byte[] authPolicyLengthBytes = new byte[2];
        byte[] symmetricBytes = new byte[2];
        byte[] schemeBytes = new byte[2];
        byte[] keyBitsBytes;    // rsa key
        byte[] exponentBytes;   // rsa key
        byte[] curveIdBytes;    // ecc key
        byte[] kdfBytes;    //ecc key
        byte[] uniqueLengthBytes = new byte[2];
        byte[] uniqueBytes;

        ByteArrayInputStream inputStream = new ByteArrayInputStream(pubArea);

        inputStream.read(typeBytes);    // type
        int type = UnsignedUtil.readUINT16BE(typeBytes);
        inputStream.read(nameAlgBytes); // name alg
        TpmHashAlgorithm nameAlg =
                TpmHashAlgorithm.fromValue(UnsignedUtil.readUINT16BE(nameAlgBytes));
        inputStream.read(objectAttributesBytes);    // object attributes
        int objectAttributesFlags = (int) UnsignedUtil.readUINT32BE(objectAttributesBytes);
        ObjectAttributes objectAttributes = parseObjectAttributes(objectAttributesFlags);
        // skip auth policy
        inputStream.read(authPolicyLengthBytes);
        int authPolicyLength = UnsignedUtil.readUINT16BE(authPolicyLengthBytes);
        if (authPolicyLength > 0) {
            inputStream.skip(authPolicyLength);
        }

        // read parameters depending on the key type
        Parameters parameters = null;
        if (type == TpmKeyAlgorithm.RSA.getValue()) {
            keyBitsBytes = new byte[2];
            exponentBytes = new byte[4];
            inputStream.read(symmetricBytes);
            inputStream.read(schemeBytes);
            inputStream.read(keyBitsBytes);
            inputStream.read(exponentBytes);
            parameters = new RsaParameters();
            parameters.setSymmetric(symmetricBytes);
            parameters.setScheme(TpmSignatureAlgorithm.fromValue(UnsignedUtil.readUINT16BE(schemeBytes)));
            ((RsaParameters) parameters).setKeyBits(keyBitsBytes);
            ((RsaParameters) parameters).setExponent(exponentBytes);
        } else if (type == TpmKeyAlgorithm.ECC.getValue()) {
            curveIdBytes = new byte[2];
            kdfBytes = new byte[2];
            inputStream.read(symmetricBytes);
            inputStream.read(schemeBytes);
            inputStream.read(curveIdBytes);
            inputStream.read(kdfBytes);
            parameters = new EccParameters();
            parameters.setSymmetric(symmetricBytes);
            parameters.setScheme(TpmSignatureAlgorithm.fromValue(UnsignedUtil.readUINT16BE(schemeBytes)));
            ((EccParameters) parameters).setCurveId(TpmEccCurve.fromValue(UnsignedUtil.readUINT16BE(curveIdBytes)));
            ((EccParameters) parameters).setKdf(kdfBytes);
        } else {
            // invalid
        }

        // read unique (key value)
        inputStream.read(uniqueLengthBytes);
        int uniqueLength = UnsignedUtil.readUINT16BE(uniqueLengthBytes);
        uniqueBytes = new byte[uniqueLength];
        inputStream.read(uniqueBytes);

        return PubArea
                .builder()
                .type(TpmKeyAlgorithm.fromValue(type))
                .nameAlg(nameAlg)
                .objectAttributes(objectAttributes)
                .parameters(parameters)
                .unique(uniqueBytes)
                .build();
    }

    public static ClockInfo parseClockInfo(byte[] clockInfo) throws IOException {
        byte[] clockBytes = new byte[8];
        byte[] resetCountBytes = new byte[4];
        byte[] restartCountBytes = new byte[4];
        byte[] safeBytes = new byte[1];

        ByteArrayInputStream inputStream = new ByteArrayInputStream(clockInfo);
        inputStream.read(clockBytes);
        inputStream.read(resetCountBytes);
        inputStream.read(restartCountBytes);
        inputStream.read(restartCountBytes);
        inputStream.read(safeBytes);

        return ClockInfo
                .builder()
                .clock(clockBytes)
                .resetCount(UnsignedUtil.readUINT32BE(resetCountBytes))
                .restartCount(UnsignedUtil.readUINT32BE(restartCountBytes))
                .safe(safeBytes[0] == 1)
                .build();
    }

    public static ObjectAttributes parseObjectAttributes(int flags) {
        return ObjectAttributes
                .builder()
                .fixedTpm(TpmObjectAttributeParser.fixedTPM(flags))
                .stClear(TpmObjectAttributeParser.stClear(flags))
                .fixedParent(TpmObjectAttributeParser.fixedParent(flags))
                .sensitiveDataOrigin(TpmObjectAttributeParser.sensitiveDataOrigin(flags))
                .userWithAuth(TpmObjectAttributeParser.userWithAuth(flags))
                .adminWithPolicy(TpmObjectAttributeParser.adminWithPolicy(flags))
                .noDA(TpmObjectAttributeParser.noDA(flags))
                .encryptedDuplication(TpmObjectAttributeParser.encryptedDuplication(flags))
                .restricted(TpmObjectAttributeParser.restricted(flags))
                .decrypt(TpmObjectAttributeParser.decrypt(flags))
                .signEncrypt(TpmObjectAttributeParser.signEncrypt(flags))
                .build();
    }

    public static AttestedName parseAttestedName(byte[] attestedNameBytes) throws IOException {
        byte[] nameBytes = new byte[2];
        byte[] hashBytes = new byte[attestedNameBytes.length - 2];

        ByteArrayInputStream inputStream = new ByteArrayInputStream(attestedNameBytes);
        inputStream.read(nameBytes);
        inputStream.read(hashBytes);

        return AttestedName
                .builder()
                .name(TpmHashAlgorithm.fromValue(UnsignedUtil.readUINT16BE(nameBytes)))
                .hash(hashBytes)
                .build();
    }
}
