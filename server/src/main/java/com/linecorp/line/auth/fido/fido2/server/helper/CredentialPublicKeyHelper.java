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

import com.linecorp.line.auth.fido.fido2.common.server.COSEAlgorithm;
import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;
import com.linecorp.line.auth.fido.fido2.server.exception.FIDO2ServerRuntimeException;
import com.linecorp.line.auth.fido.fido2.server.model.*;
import com.linecorp.line.auth.fido.fido2.server.util.PublicKeyUtil;

public class CredentialPublicKeyHelper {
    public static PublicKey convert(CredentialPublicKey credentialPublicKey) {
        PublicKey publicKey;
        if (credentialPublicKey instanceof RSAKey) {
            RSAKey rsaKey = (RSAKey) credentialPublicKey;
            // convert
            try {
                publicKey = PublicKeyUtil.getRSAPublicKey(rsaKey.getN(), rsaKey.getE());
            } catch (GeneralSecurityException e) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.USER_PUBLIC_KEY_INVALID_KEY_SPEC, e);
            }
        } else if (credentialPublicKey instanceof ECCKey) {
            ECCKey eccKey = (ECCKey) credentialPublicKey;
            // convert
            try {
                publicKey = PublicKeyUtil.getECDSAPublicKey(eccKey.getX(), eccKey.getY(), eccKey.getCurve().getNamedCurve());
            } catch (GeneralSecurityException e) {
                throw new FIDO2ServerRuntimeException(
                        InternalErrorCode.USER_PUBLIC_KEY_INVALID_KEY_SPEC, e);
            }

        } else if (credentialPublicKey instanceof OctetKey) {
            OctetKey octetKey = (OctetKey) credentialPublicKey;
            // convert
            try {
                publicKey = PublicKeyUtil.getEdDSAPublicKey(octetKey.getX(), octetKey.getCurve().getNamedCurve());
            } catch (GeneralSecurityException e) {
                throw new FIDO2ServerRuntimeException(
                        InternalErrorCode.USER_PUBLIC_KEY_INVALID_KEY_SPEC, e);
            }
        } else {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_CREDENTIAL_INSTANCE);
        }
        return publicKey;
    }

    public static COSEAlgorithm getCOSEAlgorithm(CredentialPublicKey credentialPublicKey) {
        COSEAlgorithm algorithm;
        if (credentialPublicKey instanceof RSAKey) {
            algorithm = ((RSAKey) credentialPublicKey).getAlgorithm();
        } else if (credentialPublicKey instanceof OctetKey) {
            algorithm = ((OctetKey) credentialPublicKey).getAlgorithm();
        } else {
            algorithm = ((ECCKey) credentialPublicKey).getAlgorithm();
        }
        return algorithm;
    }
}
