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

package com.linecorp.line.auth.fido.fido2.server.exception;

import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;

import lombok.Getter;

@Getter
public class FIDO2ServerRuntimeException extends RuntimeException {
    private static final long serialVersionUID = -2575717184560818381L;
    private final InternalErrorCode errorCode;

    public FIDO2ServerRuntimeException(InternalErrorCode errorCode) {
        this.errorCode = errorCode;
    }

    public FIDO2ServerRuntimeException(InternalErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public FIDO2ServerRuntimeException(InternalErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public FIDO2ServerRuntimeException(InternalErrorCode errorCode, Throwable cause) {
        super(cause);
        this.errorCode = errorCode;
    }

    public static FIDO2ServerRuntimeException makeInternalServerError(Throwable cause) {
        return new FIDO2ServerRuntimeException(InternalErrorCode.INTERNAL_SERVER_ERROR, cause);
    }

    public static FIDO2ServerRuntimeException makeCryptoError(Throwable cause) {
        return new FIDO2ServerRuntimeException(InternalErrorCode.CRYPTO_OPERATION_EXCEPTION, cause);
    }

    public static FIDO2ServerRuntimeException makeCredNotFound(String rpId, String credentialId) {
        throw new FIDO2ServerRuntimeException(InternalErrorCode.CREDENTIAL_NOT_FOUND,
                "RpId: " + rpId + "; CredentialId: " + credentialId);
    }

    public static FIDO2ServerRuntimeException makeCredNotFoundUser(String rpId, String userId) {
        throw new FIDO2ServerRuntimeException(InternalErrorCode.CREDENTIAL_NOT_FOUND,
                "RpId: " + rpId + "; UserId: " + userId);
    }

}
