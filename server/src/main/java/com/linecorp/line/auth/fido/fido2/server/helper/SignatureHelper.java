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

package com.linecorp.line.auth.fido.fido2.server.helper;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import com.linecorp.line.auth.fido.fido2.server.util.SignatureUtil;
import com.linecorp.line.auth.fido.fido2.common.server.COSEAlgorithm;
import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;
import com.linecorp.line.auth.fido.fido2.server.exception.FIDO2ServerRuntimeException;

public class SignatureHelper {
    public static boolean verifySignature(PublicKey publicKey, byte[] messageBytes, byte[] signatureBytes, COSEAlgorithm algorithm) {
        try {
            if (algorithm == COSEAlgorithm.ES256 ||
                algorithm == COSEAlgorithm.ES256K) {
                return SignatureUtil.verifySHA256withECDSA(publicKey, messageBytes, signatureBytes);
            } else if (algorithm == COSEAlgorithm.ES384) {
                return SignatureUtil.verifySHA384withECDSA(publicKey, messageBytes, signatureBytes);
            } else if (algorithm == COSEAlgorithm.ES512) {
                return SignatureUtil.verifySHA512withECDSA(publicKey, messageBytes, signatureBytes);
            } else if (algorithm == COSEAlgorithm.PS256) {
                return SignatureUtil.verifySHA256withRSAPssSignature(publicKey, messageBytes, signatureBytes);
            } else if (algorithm == COSEAlgorithm.PS384) {
                return SignatureUtil.verifySHA384withRSAPssSignature(publicKey, messageBytes, signatureBytes);
            } else if (algorithm == COSEAlgorithm.PS512) {
                return SignatureUtil.verifySHA512withRSAPssSignature(publicKey, messageBytes, signatureBytes);
            } else if (algorithm == COSEAlgorithm.RS1) {
                return SignatureUtil.verifySHA1withRSASignature(publicKey, messageBytes, signatureBytes);
            } else if (algorithm == COSEAlgorithm.RS256) {
                return SignatureUtil.verifySHA256withRSASignature(publicKey, messageBytes, signatureBytes);
            } else if (algorithm == COSEAlgorithm.RS384) {
                return SignatureUtil.verifySHA384withRSASignature(publicKey, messageBytes, signatureBytes);
            } else if (algorithm == COSEAlgorithm.RS512) {
                return SignatureUtil.verifySHA512withRSASignature(publicKey, messageBytes, signatureBytes);
            } else if (algorithm == COSEAlgorithm.EDDSA) {
                return SignatureUtil.verifyPureEdDSA(publicKey, messageBytes, signatureBytes);
            }
        } catch (GeneralSecurityException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.SIGNATURE_VERIFICATION_ERROR);
        }

        return false;
    }
}
