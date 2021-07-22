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

import com.linecorp.line.auth.fido.fido2.common.PublicKeyCredentialType;
import com.linecorp.line.auth.fido.fido2.common.server.AuthOptionRequest;
import com.linecorp.line.auth.fido.fido2.common.server.RegOptionRequest;
import com.linecorp.line.auth.fido.fido2.common.server.RegisterCredential;
import com.linecorp.line.auth.fido.fido2.common.server.VerifyCredential;
import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;
import com.linecorp.line.auth.fido.fido2.server.exception.FIDO2ServerRuntimeException;
import org.springframework.util.StringUtils;

import java.util.Base64;

public class ReqMsgVerifier {
    public static void validateRegisterCredential(RegisterCredential registerCredential) {
        if (registerCredential == null) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "registerCredential should not be null");
        }

        if (StringUtils.isEmpty(registerCredential.getOrigin())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "origin should not be null or empty");
        }

        if (StringUtils.isEmpty(registerCredential.getRpId())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "rpId should not be null or empty");
        }

        if (StringUtils.isEmpty(registerCredential.getSessionId())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "sessionId should not be null or empty");
        }

        if (registerCredential.getServerPublicKeyCredential() == null) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "serverPublicKeyCredential should not be null");
        }

        // serverPublicKeyCredential
        if (registerCredential.getServerPublicKeyCredential().getType() == null ||
                registerCredential.getServerPublicKeyCredential().getType() != PublicKeyCredentialType.PUBLIC_KEY) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "serverPublicKeyCredential.type should be 'public-key'");
        }

        if (StringUtils.isEmpty(registerCredential.getServerPublicKeyCredential().getId())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "serverPublicKeyCredential.id should not be null or empty");
        }

        try {
            Base64.getUrlDecoder().decode(registerCredential.getServerPublicKeyCredential().getId());
        } catch (IllegalArgumentException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "serverPublicKeyCredential.id should be base64 url encoded");
        }

        // serverPublicKeyCredential.response
        if (registerCredential.getServerPublicKeyCredential().getResponse() == null) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "serverPublicKeyCredential.response should not be null");
        }

        if (StringUtils.isEmpty(registerCredential.getServerPublicKeyCredential().getResponse().getAttestationObject())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "serverPublicKeyCredential.response.attestationObject should not be null or empty");
        }

        if (StringUtils.isEmpty(registerCredential.getServerPublicKeyCredential().getResponse().getClientDataJSON())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "serverPublicKeyCredential.response.clientDataJSON should not be null or empty");
        }

        try {
            Base64.getUrlDecoder().decode(registerCredential.getServerPublicKeyCredential().getResponse().getAttestationObject());
        } catch (IllegalArgumentException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "serverPublicKeyCredential.response.attestationObject should be base64 url encoded");
        }

        try {
            Base64.getUrlDecoder().decode(registerCredential.getServerPublicKeyCredential().getResponse().getClientDataJSON());
        } catch (IllegalArgumentException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "serverPublicKeyCredential.response.clientDataJSON should be base64 url encoded");
        }
    }

    public static void validateVerifyCredential(VerifyCredential verifyCredential) {
        if (verifyCredential == null) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "verifyCredential should not be null");
        }

        if (StringUtils.isEmpty(verifyCredential.getOrigin())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "origin should not be null or empty");
        }

        if (StringUtils.isEmpty(verifyCredential.getRpId())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "rpId should not be null or empty");
        }

        if (StringUtils.isEmpty(verifyCredential.getSessionId())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "sessionId should not be null or empty");
        }

        // serverPublicKeyCredential
        if (verifyCredential.getServerPublicKeyCredential() == null) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "serverPublicKeyCredential should not be null");
        }

        if (verifyCredential.getServerPublicKeyCredential().getType() == null ||
                verifyCredential.getServerPublicKeyCredential().getType() != PublicKeyCredentialType.PUBLIC_KEY) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "serverPublicKeyCredential.type should be 'public-key'");
        }

        if (StringUtils.isEmpty(verifyCredential.getServerPublicKeyCredential().getId())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "serverPublicKeyCredential.id should not be null or empty");
        }

        if (verifyCredential.getServerPublicKeyCredential().getResponse() == null) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "serverPublicKeyCredential.response should not be null");
        }

        // serverPublicKeyCredential.response
        if (StringUtils.isEmpty(verifyCredential.getServerPublicKeyCredential().getResponse().getAuthenticatorData())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "serverPublicKeyCredential.response.authenticatorData should not be null or empty");
        }

        if (StringUtils.isEmpty(verifyCredential.getServerPublicKeyCredential().getResponse().getSignature())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "serverPublicKeyCredential.response.signature should not be null or empty");
        }

        if (StringUtils.isEmpty(verifyCredential.getServerPublicKeyCredential().getResponse().getClientDataJSON())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "serverPublicKeyCredential.response.clientDataJSON should not be null or empty");
        }

        try {
            Base64.getUrlDecoder().decode(verifyCredential.getServerPublicKeyCredential().getResponse().getAuthenticatorData());
        } catch (IllegalArgumentException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "serverPublicKeyCredential.response.authenticatorData should be base64 url encoded");
        }

        try {
            Base64.getUrlDecoder().decode(verifyCredential.getServerPublicKeyCredential().getResponse().getSignature());
        } catch (IllegalArgumentException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "serverPublicKeyCredential.response.signature should be base64 url encoded");
        }

        try {
            Base64.getUrlDecoder().decode(verifyCredential.getServerPublicKeyCredential().getResponse().getClientDataJSON());
        } catch (IllegalArgumentException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "serverPublicKeyCredential.response.clientDataJSON should be base64 url encoded");
        }
    }

    public static void validateRegOptionRequest(RegOptionRequest regOptionRequest) {
        // validation
        if (regOptionRequest.getRp() == null ||
                regOptionRequest.getUser() == null) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY);
        }

        if (regOptionRequest.getUser().getId() == null) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "userId should not be null");
        }
        if (!(regOptionRequest.getUser().getId().length() > 0 && regOptionRequest.getUser().getId().length() < 64)) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY, "userId length must be between 1 and 64 bytes");
        }
    }

    public static void validateAuthOptionRequest(AuthOptionRequest authOptionRequest) {
        if (!StringUtils.hasText(authOptionRequest.getRpId())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_REQUEST_BODY);
        }
    }
}
